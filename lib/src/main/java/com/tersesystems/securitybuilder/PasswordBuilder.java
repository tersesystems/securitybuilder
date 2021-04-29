package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Creates an encrypted password.  This is a wrapper around SecretKeyFactory.
 *
 * Please see the
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider">SunJCE Provider</a>
 * for the options.
 *
 * In practice, PBKDF2 with a SHA-2 hash is as weak as you could allow, and given the choice you would
 * be much better picking Argon2 / scrypt / bcrypt over PBKDF2.
 */
public class PasswordBuilder {

  public static InitialStage builder() {
    return new InitialStageImpl();
  }

  public interface InitialStage {

    PasswordStage withAlgorithm(String algorithm);

    PasswordStage withAlgorithmAndProvider(String algorithm, String provider);

    PasswordStage withPBKDF2WithHmacSHA256();

    PasswordStage withPBKDF2WithHmacSHA384();

    PasswordStage withPBKDF2WithHmacSHA512();
  }

  public interface PasswordStage {

    IterationStage withPassword(char[] passwords);
  }

  public interface IterationStage {
    SaltStage withIterations(int iterations);
  }

  public interface SaltStage {
    KeyLengthStage withSalt(byte[] salt);
  }

  public interface KeyLengthStage {
    BuildFinal withKeyLength(int keyLength);
  }

  public interface BuildFinal {
    PBEKey build() throws GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {

    @Override
    public PasswordStage withAlgorithm(final String algorithm) {
      return new PasswordStageImpl(() -> SecretKeyFactory.getInstance(algorithm));
    }

    @Override
    public PasswordStage withAlgorithmAndProvider(final String algorithm, final String provider) {
      return new PasswordStageImpl(() -> SecretKeyFactory.getInstance(algorithm, provider));
    }

    @Override
    public PasswordStage withPBKDF2WithHmacSHA256() {
      return new PasswordStageImpl(() -> SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"));
    }

    @Override
    public PasswordStage withPBKDF2WithHmacSHA384() {
      return new PasswordStageImpl(() -> SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384"));
    }

    @Override
    public PasswordStage withPBKDF2WithHmacSHA512() {
      return new PasswordStageImpl(() -> SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512"));
    }

  }

  private static class PasswordStageImpl implements PasswordStage {

    private final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier;

    PasswordStageImpl(
        final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public IterationStage withPassword(char[] password) {
      return new IterationStageImpl(supplier, password);
    }
  }

  private static class IterationStageImpl implements IterationStage {

    private final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier;
    private final char[] password;

    IterationStageImpl(
        final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier,
        final char[] password) {

      this.supplier = supplier;
      this.password = password;
    }

    @Override
    public SaltStage withIterations(final int iterations) {
      return new SaltStageImpl(supplier, password, iterations);
    }
  }

  private static class SaltStageImpl implements SaltStage {

    private final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier;
    private final char[] password;
    private final int iterations;

    SaltStageImpl(
        final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier,
        final char[] password, final int iterations) {

      this.supplier = supplier;
      this.password = password;
      this.iterations = iterations;
    }

    @Override
    public KeyLengthStage withSalt(final byte[] salt) {
      return new KeyLengthStageImpl(supplier, password, iterations, salt);
    }
  }

  private static class KeyLengthStageImpl implements KeyLengthStage {

    private final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier;
    private final char[] password;
    private final int iterations;
    private final byte[] salt;

    KeyLengthStageImpl(
        final SupplierWithThrowable<SecretKeyFactory, GeneralSecurityException> supplier,
        final char[] password, final int iterations, final byte[] salt) {

      this.supplier = supplier;
      this.password = password;
      this.iterations = iterations;
      this.salt = salt;
    }

    @Override
    public BuildFinal withKeyLength(final int keyLength) {
      return new SecretKeySpecBuildFinal(() -> (PBEKey) supplier.getWithThrowable()
          .generateSecret(new PBEKeySpec(password, salt, iterations, keyLength)));
    }
  }

  private static class SecretKeySpecBuildFinal implements BuildFinal {

    private final SupplierWithThrowable<PBEKey, GeneralSecurityException> keySpecSupplier;

    SecretKeySpecBuildFinal(
        final SupplierWithThrowable<PBEKey, GeneralSecurityException> keySpecSupplier) {
      this.keySpecSupplier = keySpecSupplier;
    }

    public PBEKey build() throws GeneralSecurityException {
      return keySpecSupplier.getWithThrowable();
    }
  }

  private static class SecretKeyFactoryBuildFinal implements BuildFinal {

    private final SupplierWithThrowable<PBEKey, GeneralSecurityException> secretKeySupplier;

    SecretKeyFactoryBuildFinal(
        final SupplierWithThrowable<PBEKey, GeneralSecurityException> secretKeySupplier) {
      this.secretKeySupplier = secretKeySupplier;
    }

    public PBEKey build() throws GeneralSecurityException {
      return secretKeySupplier.getWithThrowable();
    }
  }

}
