package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slieb.throwables.FunctionWithThrowable;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Constitutes an secret key from inputs. This is a wrapper around SecretKeySpec.
 *
 * <p>Please see the <a
 * href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider">SunJCE
 * Provider</a> for most of the decent options. In practice, this means AES.
 *
 * <p>If you are generating a new secret key, use SecretKeyGenerator.
 *
 * <p>If you are creating secret keys from passwords, use the PasswordBuilder.
 */
public class SecretKeyBuilder {

  public interface InitialStage {

    DataStage withAES();

    /** Uses an algorithm for SecretKeySpec. */
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

  private static class InitialStageImpl implements InitialStage {

    @Override
    public DataStage withSecretKeySpec(final String algorithm) {
      return new SecretKeySpecDataStageImpl(bytes -> new SecretKeySpec(bytes, algorithm));
    }

    @Override
    public DataStage withAES() {
      return new SecretKeySpecDataStageImpl(bytes -> new SecretKeySpec(bytes, "AES"));
    }
  }

  private static class SecretKeySpecDataStageImpl implements DataStage {

    private final FunctionWithThrowable<byte[], SecretKey, GeneralSecurityException>
        keySpecFunction;

    SecretKeySpecDataStageImpl(
        final FunctionWithThrowable<byte[], SecretKey, GeneralSecurityException> keySpecFunction) {
      this.keySpecFunction = keySpecFunction;
    }

    @Override
    public BuildFinal withData(final byte[] bytes) {
      return new SecretKeySpecBuildFinal(() -> keySpecFunction.apply(bytes));
    }
  }

  private static class SecretKeySpecBuildFinal<T extends SecretKey> implements BuildFinal {

    private final SupplierWithThrowable<SecretKey, GeneralSecurityException> keySpecSupplier;

    SecretKeySpecBuildFinal(
        final SupplierWithThrowable<SecretKey, GeneralSecurityException> keySpecSupplier) {
      this.keySpecSupplier = keySpecSupplier;
    }

    public SecretKey build() throws GeneralSecurityException {
      return keySpecSupplier.getWithThrowable();
    }
  }

  private static class SecretKeyFactoryBuildFinal implements BuildFinal {

    private final SupplierWithThrowable<SecretKey, GeneralSecurityException> secretKeySupplier;

    SecretKeyFactoryBuildFinal(
        final SupplierWithThrowable<SecretKey, GeneralSecurityException> secretKeySupplier) {
      this.secretKeySupplier = secretKeySupplier;
    }

    public SecretKey build() throws GeneralSecurityException {
      return secretKeySupplier.getWithThrowable();
    }
  }

  public static InitialStage builder() {
    return new InitialStageImpl();
  }
}
