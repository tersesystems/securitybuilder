package com.tersesystems.securitybuilder;

import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.SupplierWithThrowable;

public class SignatureBuilder {

  public interface InstanceStage {
    @NotNull
    InitializeStage withAlgorithm(String algorithm);

    @NotNull
    InitializeStage withAlgorithmAndProvider(String algorithm, String provider);
  }

  public interface InitializeStage {
    @NotNull
    BuildFinal signing(PrivateKey privateKey);

    @NotNull
    BuildFinal signing(PrivateKey privateKey, SecureRandom secureRandom);

    @NotNull
    BuildFinal verifying(Certificate certificate);

    @NotNull
    BuildFinal verifying(PublicKey publicKey);
  }

  public interface BuildFinal {
    @NotNull
    BuildFinal setParameter(AlgorithmParameterSpec params);

    Signature build() throws GeneralSecurityException;
  }

  static class InstanceStageImpl extends InstanceGenerator<Signature, GeneralSecurityException>
      implements InstanceStage {
    @NotNull
    @Override
    public InitializeStage withAlgorithm(final String algorithm) {
      return new InitializeStageImpl(getInstance().withAlgorithm(algorithm));
    }

    @NotNull
    @Override
    public InitializeStage withAlgorithmAndProvider(final String algorithm, final String provider) {
      return new InitializeStageImpl(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }
  }

  static class InitializeStageImpl implements InitializeStage {
    private final SupplierWithThrowable<Signature, GeneralSecurityException> supplier;

    public InitializeStageImpl(
        final SupplierWithThrowable<Signature, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal signing(final PrivateKey privateKey) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initSign(privateKey);
            return signature;
          });
    }

    @NotNull
    @Override
    public BuildFinal signing(final PrivateKey privateKey, final SecureRandom secureRandom) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initSign(privateKey, secureRandom);
            return signature;
          });
    }

    @NotNull
    @Override
    public BuildFinal verifying(@NotNull final Certificate certificate) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initVerify(certificate);
            return signature;
          });
    }

    @NotNull
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

    @NotNull
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

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
