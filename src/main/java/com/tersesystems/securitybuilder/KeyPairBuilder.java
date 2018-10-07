package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.SupplierWithThrowable;

public class KeyPairBuilder {

  public interface InstanceStage {
    @NotNull
    <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(String algorithm);

    @NotNull
    <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(String algorithm, String provider);

    @NotNull
    InitializeStage<RSAKeyPair> withRSA();

    @NotNull
    InitializeStage<ECKeyPair> withEC();

    @NotNull
    InitializeStage<DSAKeyPair> withDSA();
  }

  public interface InitializeStage<SKP extends KeyPair<?, ?>> {

    @NotNull
    BuildFinal<SKP> withKeySize(int keySize);

    @NotNull
    BuildFinal<SKP> withKeySizeAndSecureRandom(int keySize, SecureRandom sr);

    @NotNull
    BuildFinal<SKP> withKeySpec(AlgorithmParameterSpec spec);

    @NotNull
    BuildFinal<SKP> withKeySpecAndSecureRandom(AlgorithmParameterSpec spec, SecureRandom sr);
  }

  public interface BuildFinal<SKP extends KeyPair<?, ?>> {
    SKP build() throws GeneralSecurityException;
  }

  static class InstanceStageImpl
      extends InstanceGenerator<KeyPairGenerator, GeneralSecurityException>
      implements InstanceStage {

    @NotNull
    @Override
    public <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(final String algorithm) {
      return new InitializeStageImpl<>(
          getInstance().withAlgorithm(algorithm), keyPair -> (KP) KeyPair.create(keyPair));
    }

    @NotNull
    @Override
    public <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(
        final String algorithm, final String provider) {
      return new InitializeStageImpl<>(
          getInstance().withAlgorithmAndProvider(algorithm, provider),
          keyPair -> (KP) KeyPair.create(keyPair));
    }

    @NotNull
    @Override
    public InitializeStage<RSAKeyPair> withRSA() {
      return new InitializeStageImpl<>(getInstance().withAlgorithm("RSA"), RSAKeyPair::create);
    }

    @NotNull
    @Override
    public InitializeStage<ECKeyPair> withEC() {
      return new InitializeStageImpl<>(getInstance().withAlgorithm("EC"), ECKeyPair::create);
    }

    @NotNull
    @Override
    public InitializeStage<DSAKeyPair> withDSA() {
      return new InitializeStageImpl<>(getInstance().withAlgorithm("DSA"), DSAKeyPair::create);
    }
  }

  static class InitializeStageImpl<KP extends KeyPair<?, ?>> implements InitializeStage<KP> {
    private final SupplierWithThrowable<KeyPairGenerator, GeneralSecurityException> supplier;
    private final Function<java.security.KeyPair, KP> transform;

    InitializeStageImpl(
        final SupplierWithThrowable<KeyPairGenerator, GeneralSecurityException> supplier,
        final Function<java.security.KeyPair, KP> transform) {
      this.supplier = supplier;
      this.transform = transform;
    }

    @NotNull
    @Override
    public BuildFinal<KP> withKeySize(final int keySize) {
      return new BuildFinalImpl<>(
          () -> {
            final KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(keySize);
            return kpg;
          },
          transform);
    }

    @NotNull
    @Override
    public BuildFinal<KP> withKeySizeAndSecureRandom(final int keySize, final SecureRandom sr) {
      return new BuildFinalImpl<>(
          () -> {
            final KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(keySize, sr);
            return kpg;
          },
          transform);
    }

    @NotNull
    @Override
    public BuildFinal<KP> withKeySpec(final AlgorithmParameterSpec spec) {
      return new BuildFinalImpl<>(
          () -> {
            final KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(spec);
            return kpg;
          },
          transform);
    }

    @NotNull
    @Override
    public BuildFinal<KP> withKeySpecAndSecureRandom(
        final AlgorithmParameterSpec spec, final SecureRandom sr) {
      return new BuildFinalImpl<>(
          () -> {
            final KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(spec, sr);
            return kpg;
          },
          transform);
    }
  }

  static class BuildFinalImpl<KP extends KeyPair<?, ?>> implements BuildFinal<KP> {
    private final SupplierWithThrowable<KeyPairGenerator, GeneralSecurityException> supplier;
    private final Function<java.security.KeyPair, KP> transform;

    BuildFinalImpl(
        final SupplierWithThrowable<KeyPairGenerator, GeneralSecurityException> supplier,
        Function<java.security.KeyPair, KP> transform) {
      this.supplier = supplier;
      this.transform = transform;
    }

    @Override
    public KP build() throws GeneralSecurityException {
      final KeyPairGenerator keyPairGenerator = supplier.get();
      return transform.apply(keyPairGenerator.generateKeyPair());
    }
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
