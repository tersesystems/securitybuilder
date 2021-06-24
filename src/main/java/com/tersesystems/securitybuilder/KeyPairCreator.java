package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;
import org.slieb.throwables.SupplierWithThrowable;

/** Generates new KeyPair. Use with AlgorithmParameterGenerator if you need more inputs. */
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

    InitializeStage<DHKeyPair> withDH();
  }

  public interface InitializeStage<SKP extends KeyPair<?, ?>> {
    FinalStage<SKP> withKeySize(int keySize);

    FinalStage<SKP> withKeySizeAndSecureRandom(int keySize, SecureRandom sr);

    FinalStage<SKP> withKeySpec(AlgorithmParameterSpec spec);

    FinalStage<SKP> withKeySpecAndSecureRandom(AlgorithmParameterSpec spec, SecureRandom sr);
  }

  public interface FinalStage<SKP extends KeyPair<?, ?>> {
    SKP create() throws GeneralSecurityException;
  }

  private static class InstanceStageImpl
      extends InstanceGenerator<java.security.KeyPairGenerator, GeneralSecurityException>
      implements InstanceStage {

    @Override
    @SuppressWarnings("unchecked")
    public <KP extends KeyPair<?, ?>> InitializeStage<KP> withAlgorithm(final String algorithm) {
      return new InitializeStageImpl<>(
          getInstance().withAlgorithm(algorithm), keyPair -> (KP) KeyPair.create(keyPair));
    }

    @Override
    @SuppressWarnings("unchecked")
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

    @Override
    public InitializeStage<DHKeyPair> withDH() {
      return new InitializeStageImpl<>(getInstance().withAlgorithm("DH"), DHKeyPair::create);
    }
  }

  private static class InitializeStageImpl<KP extends KeyPair<?, ?>>
      implements InitializeStage<KP> {

    private final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException>
        supplier;
    private final Function<java.security.KeyPair, KP> transform;

    InitializeStageImpl(
        final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException>
            supplier,
        final Function<java.security.KeyPair, KP> transform) {
      this.supplier = supplier;
      this.transform = transform;
    }

    @Override
    public FinalStage<KP> withKeySize(final int keySize) {
      return new FinalStageImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(keySize);
            return kpg;
          },
          transform);
    }

    @Override
    public FinalStage<KP> withKeySizeAndSecureRandom(final int keySize, final SecureRandom sr) {
      return new FinalStageImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(keySize, sr);
            return kpg;
          },
          transform);
    }

    @Override
    public FinalStage<KP> withKeySpec(final AlgorithmParameterSpec spec) {
      return new FinalStageImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(spec);
            return kpg;
          },
          transform);
    }

    @Override
    public FinalStage<KP> withKeySpecAndSecureRandom(
        final AlgorithmParameterSpec spec, final SecureRandom sr) {
      return new FinalStageImpl<>(
          () -> {
            final java.security.KeyPairGenerator kpg = supplier.getWithThrowable();
            kpg.initialize(spec, sr);
            return kpg;
          },
          transform);
    }
  }

  private static class FinalStageImpl<KP extends KeyPair<?, ?>> implements FinalStage<KP> {

    private final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException>
        supplier;
    private final Function<java.security.KeyPair, KP> transform;

    FinalStageImpl(
        final SupplierWithThrowable<java.security.KeyPairGenerator, GeneralSecurityException>
            supplier,
        Function<java.security.KeyPair, KP> transform) {
      this.supplier = supplier;
      this.transform = transform;
    }

    @Override
    public KP create() throws GeneralSecurityException {
      final java.security.KeyPairGenerator keyPairGenerator = supplier.get();
      return transform.apply(keyPairGenerator.generateKeyPair());
    }
  }
}
