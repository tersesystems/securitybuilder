package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import org.slieb.throwables.SupplierWithThrowable;

public class SignatureBuilder {

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {

    InitializeStage withAlgorithm(String algorithm);


    InitializeStage withAlgorithmAndProvider(String algorithm, String provider);
  }

  public interface InitializeStage {

    BuildFinal signing(PrivateKey privateKey);


    BuildFinal signing(PrivateKey privateKey, SecureRandom secureRandom);


    BuildFinal verifying(Certificate certificate);


    BuildFinal verifying(PublicKey publicKey);
  }

  public interface BuildFinal {

    BuildFinal setParameter(AlgorithmParameterSpec params);


    Signature build() throws GeneralSecurityException;
  }

  static class InstanceStageImpl extends InstanceGenerator<Signature, GeneralSecurityException>
      implements InstanceStage {

    @Override
    public InitializeStage withAlgorithm(final String algorithm) {
      return new InitializeStageImpl(getInstance().withAlgorithm(algorithm));
    }


    @Override
    public InitializeStage withAlgorithmAndProvider(final String algorithm, final String provider) {
      return new InitializeStageImpl(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }
  }

  static class InitializeStageImpl implements InitializeStage {

    private final SupplierWithThrowable<Signature, GeneralSecurityException> supplier;

    InitializeStageImpl(
        final SupplierWithThrowable<Signature, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }


    @Override
    public BuildFinal signing(final PrivateKey privateKey) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initSign(privateKey);
            return signature;
          });
    }


    @Override
    public BuildFinal signing(final PrivateKey privateKey, final SecureRandom secureRandom) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initSign(privateKey, secureRandom);
            return signature;
          });
    }


    @Override
    public BuildFinal verifying(final Certificate certificate) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initVerify(certificate);
            return signature;
          });
    }


    @Override
    public BuildFinal verifying(final PublicKey publicKey) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initVerify(publicKey);
            return signature;
          });
    }
  }

  static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<Signature, GeneralSecurityException> supplier;

    BuildFinalImpl(final SupplierWithThrowable<Signature, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }


    @Override
    public BuildFinal setParameter(final AlgorithmParameterSpec params) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.setParameter(params);
            return signature;
          });
    }


    @Override
    public Signature build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }
}
