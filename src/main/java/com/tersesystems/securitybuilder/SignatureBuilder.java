package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Creates a <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Signature">Signature</a>.
 *
 * See <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature">Standard Names</a> for signature
 * options.
 */
public class SignatureBuilder {

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {

    <PR extends PrivateKey, PU extends PublicKey> InitializeStage<PR, PU> withAlgorithm(String algorithm);

    <PR extends PrivateKey, PU extends PublicKey> InitializeStage<PR, PU> withAlgorithmAndProvider(String algorithm, String provider);

    InitializeStage<RSAPrivateKey, RSAPublicKey> withSHA256withRSA();
    InitializeStage<RSAPrivateKey, RSAPublicKey> withSHA384withRSA();
    InitializeStage<RSAPrivateKey, RSAPublicKey> withSHA512withRSA();

    InitializeStage<DSAPrivateKey, DSAPublicKey> withSHA256withDSA();
    InitializeStage<DSAPrivateKey, DSAPublicKey> withSHA512withDSA();

    InitializeStage<ECPrivateKey, ECPublicKey> withSHA256withECDSA();
    InitializeStage<ECPrivateKey, ECPublicKey> withSHA384withECDSA();
    InitializeStage<ECPrivateKey, ECPublicKey> withSHA512withECDSA();
  }

  public interface InitializeStage<PR extends PrivateKey, PU extends PublicKey> {

    BuildFinal signing(PR privateKey);

    BuildFinal signing(PR privateKey, SecureRandom secureRandom);

    BuildFinal verifying(Certificate certificate);

    BuildFinal verifying(PU publicKey);
  }

  public interface BuildFinal {
    BuildFinal setParameter(AlgorithmParameterSpec params);

    Signature build() throws GeneralSecurityException;
  }

  private static class InstanceStageImpl extends InstanceGenerator<Signature, GeneralSecurityException>
      implements InstanceStage {

    @Override
    public <PR extends PrivateKey, PU extends PublicKey> InitializeStage<PR, PU> withAlgorithm(final String algorithm) {
      return new InitializeStageImpl<>(getInstance().withAlgorithm(algorithm));
    }

    @Override
    public <PR extends PrivateKey, PU extends PublicKey> InitializeStage<PR, PU> withAlgorithmAndProvider(final String algorithm, final String provider) {
      return new InitializeStageImpl<>(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }

    @Override
    public InitializeStage<RSAPrivateKey, RSAPublicKey> withSHA256withRSA() {
      return withAlgorithm("SHA256withRSA");
    }

    @Override
    public InitializeStage<RSAPrivateKey, RSAPublicKey> withSHA384withRSA() {
      return withAlgorithm("SHA384withRSA");
    }

    @Override
    public InitializeStage<RSAPrivateKey, RSAPublicKey> withSHA512withRSA() {
      return withAlgorithm("SHA512withRSA");
    }

    @Override
    public InitializeStage<DSAPrivateKey, DSAPublicKey> withSHA256withDSA() {
      return withAlgorithm("SHA256withDSA");
    }

    @Override
    public InitializeStage<DSAPrivateKey, DSAPublicKey> withSHA512withDSA() {
      return withAlgorithm("SHA512withDSA");
    }

    @Override
    public InitializeStage<ECPrivateKey, ECPublicKey> withSHA256withECDSA() {
      return withAlgorithm("SHA256withECDSA");
    }

    @Override
    public InitializeStage<ECPrivateKey, ECPublicKey> withSHA384withECDSA() {
      return withAlgorithm("SHA384withECDSA");
    }

    @Override
    public InitializeStage<ECPrivateKey, ECPublicKey> withSHA512withECDSA() {
      return withAlgorithm("SHA512withECDSA");
    }
  }

  private static class InitializeStageImpl<PR extends PrivateKey, PU extends PublicKey> implements InitializeStage<PR, PU> {

    private final SupplierWithThrowable<Signature, GeneralSecurityException> supplier;

    InitializeStageImpl(
        final SupplierWithThrowable<Signature, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal signing(final PR privateKey) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initSign(privateKey);
            return signature;
          });
    }


    @Override
    public BuildFinal signing(final PR privateKey, final SecureRandom secureRandom) {
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
    public BuildFinal verifying(final PU publicKey) {
      return new BuildFinalImpl(
          () -> {
            final Signature signature = supplier.getWithThrowable();
            signature.initVerify(publicKey);
            return signature;
          });
    }
  }

  private static class BuildFinalImpl implements BuildFinal {

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
