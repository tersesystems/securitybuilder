package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Generates new KeyPair.
 */
public class KeyPairCreator {

  public static InstanceStage creator() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {

    <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(String algorithm);

    <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(String algorithm, String provider);

    InitializeStage<RSAKeyPair> withRSA();

    InitializeStage<ECKeyPair> withEC();

    InitializeStage<DSAKeyPair> withDSA();
  }

  public interface InitializeStage<SKP extends KeyPair<?, ?>> {


    BuildFinal<SKP> withKeySize(int keySize);


    BuildFinal<SKP> withKeySizeAndSecureRandom(int keySize, SecureRandom sr);


    BuildFinal<SKP> withKeySpec(AlgorithmParameterSpec spec);


    BuildFinal<SKP> withKeySpecAndSecureRandom(AlgorithmParameterSpec spec, SecureRandom sr);
  }

  public interface BuildFinal<SKP extends KeyPair<?, ?>> {

    SKP build() throws GeneralSecurityException;
  }

  private static class InstanceStageImpl
      extends InstanceGenerator<java.security.KeyPairGenerator, GeneralSecurityException>
      implements InstanceStage {

    @Override
    public <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(final String algorithm) {
      return new InitializeStageImpl<>(
          getInstance().withAlgorithm(algorithm), keyPair -> (KP) KeyPair.create(keyPair));
    }


    @Override
    public <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(
        final String algorithm, final String provider) {
      return new InitializeStageImpl<>(
          getInstance().withAlgorithmAndProvider(algorithm, provider),
          keyPair -> (KP) KeyPair.create(keyPair));
    }


    @Override
    public InitializeStage<RSAKeyPair> withRSA() {
      return new InitializeStageImpl<>(getInstance().withAlgorithm("RSA"), RSAKeyPair::create);
    }


    @Override
    public InitializeStage<ECKeyPair> withEC() {
      return new InitializeStageImpl<>(getInstance().withAlgorithm("EC"), ECKeyPair::create);
    }


    @Override
    public InitializeStage<DSAKeyPair> withDSA() {
      return new InitializeStageImpl<>(getInstance().withAlgorithm("DSA"), DSAKeyPair::create);
    }
  }

  private static class InitializeStageImpl<KP extends KeyPair<?, ?>> implements InitializeStage<KP> {

    private final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException> supplier;
    private final Function<java.security.KeyPair, KP> transform;

    InitializeStageImpl(
        final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException> supplier,
        final Function<java.security.KeyPair, KP> transform) {
      this.supplier = supplier;
      this.transform = transform;
    }


    @Override
    public BuildFinal<KP> withKeySize(final int keySize) {
      return new BuildFinalImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(keySize);
            return kpg;
          },
          transform);
    }


    @Override
    public BuildFinal<KP> withKeySizeAndSecureRandom(final int keySize, final SecureRandom sr) {
      return new BuildFinalImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(keySize, sr);
            return kpg;
          },
          transform);
    }


    @Override
    public BuildFinal<KP> withKeySpec(final AlgorithmParameterSpec spec) {
      return new BuildFinalImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(spec);
            return kpg;
          },
          transform);
    }


    @Override
    public BuildFinal<KP> withKeySpecAndSecureRandom(
        final AlgorithmParameterSpec spec, final SecureRandom sr) {
      return new BuildFinalImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(spec, sr);
            return kpg;
          },
          transform);
    }
  }

  private static class BuildFinalImpl<KP extends KeyPair<?, ?>> implements BuildFinal<KP> {

    private final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException> supplier;
    private final Function<java.security.KeyPair, KP> transform;

    BuildFinalImpl(
        final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException> supplier,
        Function<java.security.KeyPair, KP> transform) {
      this.supplier = supplier;
      this.transform = transform;
    }


    @Override
    public KP build() throws GeneralSecurityException {
      final java.security.KeyPairGenerator keyPairGenerator = supplier.get();
      return transform.apply(keyPairGenerator.generateKeyPair());
    }
  }
}
