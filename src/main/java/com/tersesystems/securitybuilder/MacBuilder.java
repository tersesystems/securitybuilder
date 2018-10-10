package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Builds the <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac">Mac</a>
 * class.
 */
public class MacBuilder {

  public static InitialStage builder() {
    return new InitialStageImpl();
  }

  public interface InitialStage {

    SecretKeySpecStage withHmacSHA256();

    SecretKeySpecStage withHmacSHA512();

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

    BuildFinal withString(String privateString);
  }

  public interface BuildFinal {
    Mac build() throws GeneralSecurityException;
  }

  static class InitialStageImpl implements InitialStage {

    @Override
    public SecretKeySpecStage withHmacSHA256() {
      return withSecretKeySpec("HmacSHA256");
    }

    @Override
    public SecretKeySpecStage withHmacSHA512() {
      return withSecretKeySpec("HmacSHA512");
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
    public InitializeStage withAlgorithm(final String algorithm,
        final String provider) {
      return new InitializeStageImpl(() -> Mac.getInstance(algorithm, provider));
    }
  }

  static class InitializeStageImpl implements InitializeStage {

    private final SupplierWithThrowable<Mac, GeneralSecurityException> supplier;

    InitializeStageImpl(
        final SupplierWithThrowable<Mac, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal withKey(final SecretKey key) {
      return new BuildFinalImpl(() -> {
        Mac mac = supplier.get();
        mac.init(key);
        return mac;
      });
    }

    @Override
    public BuildFinal withKeyAndSpec(final SecretKey key, final AlgorithmParameterSpec params) {
      return new BuildFinalImpl(() -> {
        Mac mac = supplier.get();
        mac.init(key, params);
        return mac;
      });
    }
  }

  static class SecretKeySpecStageImpl implements SecretKeySpecStage {
    private final SupplierWithThrowable<Mac, GeneralSecurityException> supplier;

    SecretKeySpecStageImpl(
        final SupplierWithThrowable<Mac, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal withBytes(final byte[] privateBytes) {
      return new BuildFinalImpl(() -> {
        Mac mac = supplier.get();
        mac.init(new SecretKeySpec(privateBytes, mac.getAlgorithm()));
        return mac;
      });
    }

    @Override
    public BuildFinal withString(final String privateString) {
      return new BuildFinalImpl(() -> {
        Mac mac = supplier.get();
        mac.init(new SecretKeySpec(privateString.getBytes(), mac.getAlgorithm()));
        return mac;
      });
    }
  }

  static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<Mac, GeneralSecurityException> supplier;

    BuildFinalImpl(
        final SupplierWithThrowable<Mac, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public Mac build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }
}
