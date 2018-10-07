package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.FunctionWithThrowable;
import org.slieb.throwables.SupplierWithThrowable;

public class SecretKeyBuilder {

  public interface InitialStage {

    /**
     * Uses a SecretKeyFactory algorithm, as specified in
     * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory">SecretKeyFactory Algorithms</a>.
     *
     * @param algorithm
     * @return
     */
    KeyStage withAlgorithm(String algorithm);

    KeyStage withAlgorithmAndProvider(String algorithm, String provider);

    /**
     * Uses an algorithm for SecretKeySpec.  These are based off the Cipher, and most of them are in <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#OracleUcrypto">The OracleUcrypto Provider</a>, i.e. "AES".
     *
     * @param algorithm
     * @return
     */
    DataStage withSecretKeySpec(String algorithm);
  }

  public interface KeyStage {
    BuildFinal withKeySpec(KeySpec keySpec);
  }

  public interface DataStage {
    BuildFinal withData(byte[] bytes);
  }

  public interface BuildFinal {
    SecretKey build() throws GeneralSecurityException;
  }

  static class InitialStageImpl implements InitialStage {

    @Override
    public KeyStage withAlgorithm(final String algorithm) {
      return new KeyStageImpl(() -> SecretKeyFactory.getInstance(algorithm));
    }

    @Override
    public KeyStage withAlgorithmAndProvider(final String algorithm,
        final String provider) {
      return new KeyStageImpl(() -> SecretKeyFactory.getInstance(algorithm, provider));
    }

    @Override
    public DataStage withSecretKeySpec(final String algorithm) {
      return new SecretKeySpecDataStageImpl(bytes -> new SecretKeySpec(bytes, algorithm));
    }

  }

  static class KeyStageImpl<T extends SecretKey> implements KeyStage {
    private final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> secretKeyFactorySupplier;

    KeyStageImpl(
        final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> secretKeyFactorySupplier) {
      this.secretKeyFactorySupplier = secretKeyFactorySupplier;
    }

    @Override
    public BuildFinal withKeySpec(final KeySpec keySpec) {
      return new SecretKeyFactoryBuildFinal(() -> secretKeyFactorySupplier.getWithThrowable().generateSecret(keySpec));
    }

  }

  static class SecretKeySpecDataStageImpl implements DataStage {

    private final FunctionWithThrowable<byte[], SecretKey, GeneralSecurityException> keySpecFunction;

    public SecretKeySpecDataStageImpl(final FunctionWithThrowable<byte[], SecretKey, GeneralSecurityException> keySpecFunction) {
      this.keySpecFunction = keySpecFunction;
    }

    @Override
    public BuildFinal withData(final byte[] bytes) {
      return new SecretKeySpecBuildFinal(() -> keySpecFunction.apply(bytes));
    }
  }

  static class SecretKeySpecBuildFinal<T extends SecretKey> implements BuildFinal {
    private final SupplierWithThrowable<SecretKey, GeneralSecurityException> keySpecSupplier;

    SecretKeySpecBuildFinal(final SupplierWithThrowable<SecretKey, GeneralSecurityException> keySpecSupplier) {
      this.keySpecSupplier = keySpecSupplier;
    }

    @SuppressWarnings("unchecked")
    public SecretKey build() throws GeneralSecurityException {
      return keySpecSupplier.getWithThrowable();
    }
  }

  static class SecretKeyFactoryBuildFinal implements BuildFinal {

    private final SupplierWithThrowable<SecretKey, GeneralSecurityException> secretKeySupplier;

    SecretKeyFactoryBuildFinal(
        final SupplierWithThrowable<SecretKey, GeneralSecurityException> secretKeySupplier) {
      this.secretKeySupplier = secretKeySupplier;
    }

    public SecretKey build() throws GeneralSecurityException {
      return secretKeySupplier.getWithThrowable();
    }
  }

  @NotNull
  @Contract(" -> new")
  public static InitialStage builder() {
    return new InitialStageImpl();
  }

}
