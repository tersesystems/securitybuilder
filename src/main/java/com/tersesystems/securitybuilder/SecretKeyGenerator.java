package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Generates a SecretKey using <a
 * href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator">KeyGenerator</a>
 * algorithms.
 *
 * <p>If you are pulling in an existing secret key from input, use SecretKeyBuilder.
 */
public class SecretKeyGenerator {

  public interface InitialStage {

    InitializeStage withAES();

    InitializeStage withHmacSHA1();

    InitializeStage withHmacSHA224();

    InitializeStage withHmacSHA256();

    InitializeStage withHmacSHA384();

    InitializeStage withHmacSHA512();

    InitializeStage withAlgorithm(String algorithm);

    InitializeStage withAlgorithmAndProvider(String algorithm, String provider);
  }

  public interface InitializeStage {
    BuildFinal withRandom(SecureRandom random);

    BuildFinal withKeySize(int keySize);

    BuildFinal withKeySizeAndRandom(int keySize, SecureRandom random);
  }

  public interface BuildFinal {
    SecretKey build() throws GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {

    @Override
    public InitializeStage withAES() {
      return withAlgorithm("AES");
    }

    @Override
    public InitializeStage withHmacSHA1() {
      return withAlgorithm("HmacSHA1");
    }

    @Override
    public InitializeStage withHmacSHA224() {
      return withAlgorithm("HmacSHA224");
    }

    @Override
    public InitializeStage withHmacSHA256() {
      return withAlgorithm("HmacSHA256");
    }

    @Override
    public InitializeStage withHmacSHA384() {
      return withAlgorithm("HmacSHA384");
    }

    @Override
    public InitializeStage withHmacSHA512() {
      return withAlgorithm("HmacSHA512");
    }

    @Override
    public InitializeStage withAlgorithm(final String algorithm) {
      return new InitializeStageImpl(() -> KeyGenerator.getInstance(algorithm));
    }

    @Override
    public InitializeStage withAlgorithmAndProvider(final String algorithm, final String provider) {
      return new InitializeStageImpl(() -> KeyGenerator.getInstance(algorithm, provider));
    }
  }

  private static class InitializeStageImpl implements InitializeStage {

    private final SupplierWithThrowable<KeyGenerator, GeneralSecurityException> supplier;

    InitializeStageImpl(
        final SupplierWithThrowable<KeyGenerator, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal withRandom(final SecureRandom random) {
      return new BuildFinalImpl(
          () -> {
            KeyGenerator keyGenerator = supplier.getWithThrowable();
            keyGenerator.init(random);
            return keyGenerator.generateKey();
          });
    }

    @Override
    public BuildFinal withKeySize(final int keySize) {
      return new BuildFinalImpl(
          () -> {
            KeyGenerator keyGenerator = supplier.getWithThrowable();
            keyGenerator.init(keySize);
            return keyGenerator.generateKey();
          });
    }

    @Override
    public BuildFinal withKeySizeAndRandom(final int keySize, final SecureRandom random) {
      return new BuildFinalImpl(
          () -> {
            KeyGenerator keyGenerator = supplier.getWithThrowable();
            keyGenerator.init(keySize, random);
            return keyGenerator.generateKey();
          });
    }
  }

  private static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<SecretKey, GeneralSecurityException> supplier;

    BuildFinalImpl(final SupplierWithThrowable<SecretKey, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public SecretKey build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }

  public static InitialStage generate() {
    return new InitialStageImpl();
  }
}
