package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreement;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Creates a <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyAgreement">KeyAgreement</a> instance.
 */
public class KeyAgreementBuilder {

  public interface InitialStage {
    InitStage withAlgorithm(String algorithm);
    InitStage withAlgorithmAndProvider(String algorithm, String provider);
  }

  public interface InitStage {
    BuildFinal withKey(PrivateKey key);

    BuildFinal withKeyAndSpec(PrivateKey key, AlgorithmParameterSpec params);
  }

  public interface BuildFinal {
    KeyAgreement build() throws GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {

    @Override
    public InitStage withAlgorithm(final String algorithm) {
      return new InitStageImpl(() -> KeyAgreement.getInstance(algorithm));
    }

    @Override
    public InitStage withAlgorithmAndProvider(final String algorithm, final String provider) {
      return new InitStageImpl(() -> KeyAgreement.getInstance(algorithm, provider));
    }
  }

  private static class InitStageImpl implements InitStage {
    private final SupplierWithThrowable<KeyAgreement, GeneralSecurityException> supplier;

    InitStageImpl(final SupplierWithThrowable<KeyAgreement, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal withKey(final PrivateKey key) {
      return new BuildFinalImpl(() -> {
        KeyAgreement keyAgreement = supplier.getWithThrowable();
        keyAgreement.init(key);
        return keyAgreement;
      });
    }

    @Override
    public BuildFinal withKeyAndSpec(final PrivateKey key, final AlgorithmParameterSpec params) {
      return new BuildFinalImpl(() -> {
        KeyAgreement keyAgreement = supplier.getWithThrowable();
        keyAgreement.init(key, params);
        return keyAgreement;
      });
    }
  }

  private static class BuildFinalImpl implements BuildFinal {
    private final SupplierWithThrowable<KeyAgreement, GeneralSecurityException> supplier;

    BuildFinalImpl(
        final SupplierWithThrowable<KeyAgreement, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public KeyAgreement build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }

  public static InitialStage builder() {
    return new InitialStageImpl();
  }

}
