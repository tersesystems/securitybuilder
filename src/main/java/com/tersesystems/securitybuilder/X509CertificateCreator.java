package com.tersesystems.securitybuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import sun.security.jca.JCAUtil;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Creates a new certificate.
 */
public class X509CertificateCreator {

  private X509CertificateCreator() {
  }

  public static InitialStage creator() {
    return new InitialStageImpl();
  }

  public interface InitialStage {

    <PK extends PrivateKey> NotBeforeStage<PK> withSignatureAlgorithm(
        String algorithm);


    NotBeforeStage<RSAPrivateKey> withSHA256withRSA();


    NotBeforeStage<RSAPrivateKey> withSHA384withRSA();


    NotBeforeStage<RSAPrivateKey> withSHA512withRSA();


    NotBeforeStage<ECPrivateKey> withSHA224withECDSA();


    NotBeforeStage<ECPrivateKey> withSHA256withECDSA();


    NotBeforeStage<ECPrivateKey> withSHA384withECDSA();


    NotBeforeStage<ECPrivateKey> withSHA512withECDSA();
  }

  public interface NotBeforeStage<PK extends PrivateKey> {
    NotAfterStage<PK> withNotBefore(Instant notBefore);

    NotAfterStage<PK> withNotBeforeNow();

    IssuerStage<PK> withDuration(Duration duration);

    IssuerStage<PK> withDuration(Instant notBefore, Duration duration);
  }

  public interface NotAfterStage<PK extends PrivateKey> {


    IssuerStage<PK> withNotAfter(Instant notAfter);


    IssuerStage<PK> withDuration(Duration duration);
  }

  public interface IssuerStage<PK extends PrivateKey> {


    PrivateKeyStage<PK> withIssuer(String issuer);


    PrivateKeyStage<PK> withIssuer(X509Certificate issuerCert);


    BuildFinal withRootCA(
        String dn, java.security.KeyPair keyPair, int pathLenConstraint);


    BuildFinal withRootCA(
        String dn,
        KeyPair<? extends PublicKey, PK> keyPair,
        int pathLenConstraint);
  }

  public interface PrivateKeyStage<PK extends PrivateKey> {


    PublicKeyStage withSigningKey(PK privateKey);
  }

  public interface PublicKeyStage {


    SubjectStage withPublicKey(PublicKey publicKey);
  }

  public interface SubjectStage {


    ExtensionsStage withSubject(String subject);
  }

  public interface ExtensionsStage {


    BuildFinal withExtensions(CertificateExtensions extensions);


    BuildFinal withEndEntityExtensions();


    BuildFinal withCertificateAuthorityExtensions(int pathLenConstraint);


    BuildFinal withClientCertificateExtensions();
  }

  public interface BuildFinal {
    BuildFinal withSecureRandom(SecureRandom secureRandom);

    BuildChainFinal chain();

    BuildChainFinal chain(
        PrivateKey privateKey,
        Function<PublicKeyStage, BuildChainFinal> childBuilderFunction);

    X509Certificate create() throws IOException, GeneralSecurityException;
  }

  public interface BuildChainFinal {
    X509Certificate[] create() throws IOException, GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {
    @Override
    public <PK extends PrivateKey> NotBeforeStage<PK> withSignatureAlgorithm(
        final String algorithm) {
      return new NotBeforeStageImpl<>(algorithm);
    }

    @Override
    public NotBeforeStage<RSAPrivateKey> withSHA256withRSA() {
      return new NotBeforeStageImpl<>("SHA256withRSA");
    }

    @Override
    public NotBeforeStage<RSAPrivateKey> withSHA384withRSA() {
      return new NotBeforeStageImpl<>("SHA384withRSA");
    }


    @Override
    public NotBeforeStage<RSAPrivateKey> withSHA512withRSA() {
      return new NotBeforeStageImpl<>("SHA512withRSA");
    }


    @Override
    public NotBeforeStage<ECPrivateKey> withSHA224withECDSA() {
      return new NotBeforeStageImpl<>("SHA224withECDSA");
    }


    @Override
    public NotBeforeStage<ECPrivateKey> withSHA256withECDSA() {
      return new NotBeforeStageImpl<>("SHA256withECDSA");
    }


    @Override
    public NotBeforeStage<ECPrivateKey> withSHA384withECDSA() {
      return new NotBeforeStageImpl<>("SHA384withECDSA");
    }


    @Override
    public NotBeforeStage<ECPrivateKey> withSHA512withECDSA() {
      return new NotBeforeStageImpl<>("SHA512withECDSA");
    }
  }

  private static class NotBeforeStageImpl<PK extends PrivateKey> implements NotBeforeStage<PK> {

    private final String algorithm;

    NotBeforeStageImpl(final String algorithm) {
      this.algorithm = algorithm;
    }


    @Override
    public NotAfterStage<PK> withNotBefore(final Instant notBefore) {
      return new NotAfterStageImpl<>(algorithm, notBefore);
    }


    @Override
    public NotAfterStage<PK> withNotBeforeNow() {
      return new NotAfterStageImpl<>(algorithm, Instant.now());
    }


    @Override
    public IssuerStage<PK> withDuration(final Duration duration) {
      return withDuration(Instant.now(), duration);
    }


    @Override
    public IssuerStage<PK> withDuration(
        final Instant notBefore, final Duration duration) {
      return new IssuerStageImpl<>(algorithm, notBefore, notBefore.plus(duration));
    }
  }

  private static class NotAfterStageImpl<PK extends PrivateKey> implements NotAfterStage<PK> {

    private final String algorithm;
    private final Instant notBefore;

    NotAfterStageImpl(final String algorithm, final Instant notBefore) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
    }


    @Override
    public IssuerStage<PK> withNotAfter(final Instant notAfter) {
      return new IssuerStageImpl<>(algorithm, notBefore, notAfter);
    }


    @Override
    public IssuerStage<PK> withDuration(final Duration duration) {
      return new IssuerStageImpl<>(algorithm, notBefore, notBefore.plus(duration));
    }
  }

  private static class IssuerStageImpl<PK extends PrivateKey> implements IssuerStage<PK> {

    private final String algorithm;
    private final Instant notBefore;
    private final Instant notAfter;

    IssuerStageImpl(final String algorithm, final Instant notBefore, final Instant notAfter) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
    }


    @Override
    public PrivateKeyStage<PK> withIssuer(final String issuer) {
      return new PrivateKeyStageImpl<>(algorithm, notBefore, notAfter, issuer);
    }


    @Override
    public PrivateKeyStage<PK> withIssuer(final X509Certificate issuerCert) {
      return new PrivateKeyStageImpl<>(
          algorithm, notBefore, notAfter, issuerCert.getSubjectDN().getName());
    }


    @Override
    public BuildFinal withRootCA(
        final String dn,
        final java.security.KeyPair keyPair,
        int pathLenConstraint) {
      return new ExtensionsStageImpl(
          algorithm, notBefore, notAfter, dn, keyPair.getPrivate(), keyPair.getPublic(), dn)
          .withCertificateAuthorityExtensions(pathLenConstraint);
    }


    @Override
    public BuildFinal withRootCA(
        final String dn,
        final KeyPair<? extends PublicKey, PK> keyPair,
        int pathLenConstraint) {
      return new ExtensionsStageImpl(
          algorithm, notBefore, notAfter, dn, keyPair.getPrivate(), keyPair.getPublic(), dn)
          .withCertificateAuthorityExtensions(pathLenConstraint);
    }
  }

  private static class PrivateKeyStageImpl<PK extends PrivateKey> implements PrivateKeyStage<PK> {

    private final String algorithm;
    private final String issuer;
    private final Instant notBefore;
    private final Instant notAfter;

    PrivateKeyStageImpl(
        final String algorithm,
        final Instant notBefore,
        final Instant notAfter,
        final String issuer) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      this.issuer = issuer;
    }


    @Override
    public PublicKeyStage withSigningKey(final PK privateKey) {
      return new PublicKeyStageImpl(algorithm, notBefore, notAfter, issuer, privateKey);
    }
  }

  private static class PublicKeyStageImpl implements PublicKeyStage {

    private final String algorithm;
    private final Instant notBefore;
    private final Instant notAfter;
    private final String issuer;
    private final PrivateKey privateKey;

    PublicKeyStageImpl(
        final String algorithm,
        final Instant notBefore,
        final Instant notAfter,
        final String issuer,
        final PrivateKey privateKey) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      this.issuer = issuer;
      this.privateKey = privateKey;
    }


    @Override
    public SubjectStage withPublicKey(final PublicKey publicKey) {
      return new SubjectStageImpl(algorithm, notBefore, notAfter, issuer, privateKey, publicKey);
    }
  }

  private static class SubjectStageImpl implements SubjectStage {

    private final String algorithm;
    private final Instant notBefore;
    private final Instant notAfter;
    private final String issuer;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    SubjectStageImpl(
        final String algorithm,
        final Instant notBefore,
        final Instant notAfter,
        final String issuer,
        final PrivateKey privateKey,
        final PublicKey publicKey) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      this.issuer = issuer;
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }


    @Override
    public ExtensionsStage withSubject(final String subject) {
      return new ExtensionsStageImpl(
          algorithm, notBefore, notAfter, issuer, privateKey, publicKey, subject);
    }
  }

  private static class ExtensionsStageImpl implements ExtensionsStage {

    private final String algorithm;
    private final String subject;
    private final String issuer;
    private final Instant notBefore;
    private final Instant notAfter;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    ExtensionsStageImpl(
        final String algorithm,
        final Instant notBefore,
        final Instant notAfter,
        final String issuer,
        final PrivateKey privateKey,
        final PublicKey publicKey,
        final String subject) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      this.subject = subject;
      this.issuer = issuer;
      this.publicKey = publicKey;
      this.privateKey = privateKey;
    }


    @Override
    public BuildFinal withExtensions(
        final CertificateExtensions extensions) {
      return new BuildFinalImpl(
          algorithm,
          subject,
          issuer,
          notBefore,
          notAfter,
          publicKey,
          privateKey,
          extensions,
          JCAUtil.getSecureRandom());
    }


    @Override
    public BuildFinal withEndEntityExtensions() {
      try {
        final CertificateExtensions extensions = new CertificateExtensions();
        final KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_ENCIPHERMENT, Boolean.TRUE);
        keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.TRUE);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);
        return new BuildFinalImpl(
            algorithm, subject, issuer, notBefore, notAfter, publicKey, privateKey, extensions);
      } catch (final IOException e) {
        throw new IllegalStateException(e);
      }
    }


    @Override
    public BuildFinal withCertificateAuthorityExtensions(
        int pathLenConstraint) {
      try {
        final CertificateExtensions extensions = new CertificateExtensions();
        extensions.set(
            BasicConstraintsExtension.NAME,
            new BasicConstraintsExtension(
                /* isCritical */ true, /* isCA */ true, pathLenConstraint));
        final KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_CERTSIGN, Boolean.TRUE);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);
        return new BuildFinalImpl(
            algorithm, subject, issuer, notBefore, notAfter, publicKey, privateKey, extensions);
      } catch (final IOException e) {
        throw new IllegalStateException(e);
      }
    }


    @Override
    public BuildFinal withClientCertificateExtensions() {
      try {
        final CertificateExtensions extensions = new CertificateExtensions();
        final KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.TRUE);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);
        return new BuildFinalImpl(
            algorithm, subject, issuer, notBefore, notAfter, publicKey, privateKey, extensions);
      } catch (final IOException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  private static class BuildFinalImpl implements BuildFinal {

    private final String algorithm;
    private final String subject;
    private final String issuer;
    private final Instant notBefore;
    private final Instant notAfter;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final CertificateExtensions extensions;
    private final SecureRandom secureRandom;

    BuildFinalImpl(
        final String algorithm,
        final String subject,
        final String issuer,
        final Instant notBefore,
        final Instant notAfter,
        final PublicKey publicKey,
        final PrivateKey privateKey,
        final CertificateExtensions extensions,
        final SecureRandom secureRandom) {
      this.algorithm = algorithm;
      this.subject = subject;
      this.issuer = issuer;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      this.publicKey = publicKey;
      this.privateKey = privateKey;
      this.extensions = extensions;
      this.secureRandom = secureRandom;
    }

    BuildFinalImpl(
        final String algorithm,
        final String subject,
        final String issuer,
        final Instant notBefore,
        final Instant notAfter,
        final PublicKey publicKey,
        final PrivateKey privateKey,
        final CertificateExtensions extensions) {
      this.algorithm = algorithm;
      this.subject = subject;
      this.issuer = issuer;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
      this.publicKey = publicKey;
      this.privateKey = privateKey;
      this.extensions = extensions;
      this.secureRandom = JCAUtil.getSecureRandom();
    }


    @Override
    public BuildFinal withSecureRandom(
        final SecureRandom secureRandom) {
      return new BuildFinalImpl(
          algorithm,
          subject,
          issuer,
          notBefore,
          notAfter,
          publicKey,
          privateKey,
          extensions,
          secureRandom);
    }


    @Override
    public X509Certificate create() throws GeneralSecurityException {
      try {
        final X509CertInfo info = new X509CertInfo();
        final CertificateValidity interval =
            new CertificateValidity(Date.from(notBefore), Date.from(notAfter));
        final BigInteger sn = new BigInteger(64, secureRandom);

        info.set(X509CertInfo.VALIDITY, interval);

        info.set(X509CertInfo.SUBJECT, new X500Name(subject));
        info.set(X509CertInfo.ISSUER, new X500Name(issuer));

        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(algorithm)));
        info.set(X509CertInfo.EXTENSIONS, extensions);

        // Sign the cert to identify the algorithm that's used.
        @SuppressWarnings("sunapi") final X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privateKey, algorithm);

        final AlgorithmId algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        final X509CertImpl newCert = new X509CertImpl(info);
        newCert.sign(privateKey, algorithm);
        return newCert;
      } catch (final IOException e) {
        throw new GeneralSecurityException(e.getMessage(), e);
      }
    }


    @Override
    public BuildChainFinal chain() {
      return () -> new X509Certificate[]{BuildFinalImpl.this.create()};
    }


    @Override
    public BuildChainFinal chain(
        PrivateKey issuerPrivateKey,
        final Function<PublicKeyStage, BuildChainFinal> childBuilderFunction) {
      return () -> {
        X509Certificate issuerCertificate = BuildFinalImpl.this.create();

        PublicKeyStage publicKeyStage =
            X509CertificateCreator.creator()
                .withSignatureAlgorithm(algorithm)
                .withNotBefore(notBefore)
                .withNotAfter(notAfter)
                .withIssuer(issuerCertificate)
                .withSigningKey(issuerPrivateKey);

        X509Certificate[] certs = childBuilderFunction.apply(publicKeyStage).create();
        List<X509Certificate> list = new ArrayList<>(Arrays.asList(certs));
        list.add(issuerCertificate);
        return list.toArray(new X509Certificate[0]);
      };
    }
  }
}
