package com.tersesystems.securitybuilder;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Builds the <a
 * href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac">Mac</a>
 * class.
 */
public class MacBuilder {

  public interface InitialStage {

    SecretKeySpecStage withHmacSHA256();

    SecretKeySpecStage withHmacSHA384();

    SecretKeySpecStage withHmacSHA512();

    SecretKeySpecStage withPBEWithHmacSHA256();

    SecretKeySpecStage withPBEWithHmacSHA384();

    SecretKeySpecStage withPBEWithHmacSHA512();

    SecretKeySpecStage withSecretKeySpec(String algorithm);

    InitializeStage withAlgorithm(String algorithm);

    InitializeStage withAlgorithm(String algorithm, String provider);
  }

  public interface InitializeStage {

    BuildFinal withKey(SecretKey key);

    BuildFinal withKeyAndSpec(SecretKey key, AlgorithmParameterSpec params);
  }

  public interface SecretKeySpecStage {
    BuildFinal withBytes(byte[] privateBytes);

    /** Convenience method, bytes are pulled from string using StandardCharsets.UTF_8. */
    BuildFinal withString(String privateString);
  }

  public interface BuildFinal {
    Mac build() throws GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {

    @Override
    public SecretKeySpecStage withHmacSHA256() {
      return withSecretKeySpec("HmacSHA256");
    }

    @Override
    public SecretKeySpecStage withHmacSHA384() {
      return withSecretKeySpec("HmacSHA384");
    }

    @Override
    public SecretKeySpecStage withHmacSHA512() {
      return withSecretKeySpec("HmacSHA512");
    }

    @Override
    public SecretKeySpecStage withPBEWithHmacSHA256() {
      return withSecretKeySpec("PBEWithHmacSHA256");
    }

    @Override
    public SecretKeySpecStage withPBEWithHmacSHA384() {
      return withSecretKeySpec("PBEWithHmacSHA384");
    }

    @Override
    public SecretKeySpecStage withPBEWithHmacSHA512() {
      return withSecretKeySpec("PBEWithHmacSHA512");
    }

    @Override
    public SecretKeySpecStage withSecretKeySpec(final String algorithm) {
      return new SecretKeySpecStageImpl(() -> Mac.getInstance(algorithm));
    }

    @Override
    public InitializeStage withAlgorithm(final String algorithm) {
      return new InitializeStageImpl(() -> Mac.getInstance(algorithm));
    }

    @Override
    public InitializeStage withAlgorithm(final String algorithm, final String provider) {
      return new InitializeStageImpl(() -> Mac.getInstance(algorithm, provider));
    }
  }

  private static class InitializeStageImpl implements InitializeStage {

    private final SupplierWithThrowable<Mac, GeneralSecurityException> supplier;

    InitializeStageImpl(final SupplierWithThrowable<Mac, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal withKey(final SecretKey key) {
      return new BuildFinalImpl(
          () -> {
            Mac mac = supplier.get();
            mac.init(key);
            return mac;
          });
    }

    @Override
    public BuildFinal withKeyAndSpec(final SecretKey key, final AlgorithmParameterSpec params) {
      return new BuildFinalImpl(
          () -> {
            Mac mac = supplier.get();
            mac.init(key, params);
            return mac;
          });
    }
  }

  private static class SecretKeySpecStageImpl implements SecretKeySpecStage {
    private final SupplierWithThrowable<Mac, GeneralSecurityException> supplier;

    SecretKeySpecStageImpl(final SupplierWithThrowable<Mac, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal withBytes(final byte[] privateBytes) {
      return new BuildFinalImpl(
          () -> {
            Mac mac = supplier.get();
            mac.init(new SecretKeySpec(privateBytes, mac.getAlgorithm()));
            return mac;
          });
    }

    @Override
    public BuildFinal withString(final String privateString) {
      return new BuildFinalImpl(
          () -> {
            Mac mac = supplier.get();
            mac.init(
                new SecretKeySpec(
                    privateString.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm()));
            return mac;
          });
    }
  }

  private static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<Mac, GeneralSecurityException> supplier;

    BuildFinalImpl(final SupplierWithThrowable<Mac, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public Mac build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }

  public static InitialStage builder() {
    return new InitialStageImpl();
  }
}
