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
import org.jetbrains.annotations.NotNull;
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

public class X509CertificateBuilder {

  private X509CertificateBuilder() {}

  public static InitialStage builder() {
    return new InitialStageImpl();
  }

  public interface InitialStage {

    @NotNull
    <PK extends PrivateKey> NotBeforeStage<PK> withSignatureAlgorithm(@NotNull String algorithm);

    @NotNull
    NotBeforeStage<RSAPrivateKey> withSHA256withRSA();

    @NotNull
    NotBeforeStage<RSAPrivateKey> withSHA384withRSA();

    @NotNull
    NotBeforeStage<RSAPrivateKey> withSHA512withRSA();

    @NotNull
    NotBeforeStage<ECPrivateKey> withSHA224withECDSA();

    @NotNull
    NotBeforeStage<ECPrivateKey> withSHA256withECDSA();

    @NotNull
    NotBeforeStage<ECPrivateKey> withSHA384withECDSA();

    @NotNull
    NotBeforeStage<ECPrivateKey> withSHA512withECDSA();
  }

  public interface NotBeforeStage<PK extends PrivateKey> {

    @NotNull
    NotAfterStage<PK> withNotBefore(@NotNull Instant notBefore);

    @NotNull
    NotAfterStage<PK> withNotBeforeNow();

    @NotNull
    IssuerStage<PK> withDuration(@NotNull Duration duration);

    @NotNull
    IssuerStage<PK> withDuration(@NotNull Instant notBefore, @NotNull Duration duration);
  }

  public interface NotAfterStage<PK extends PrivateKey> {

    @NotNull
    IssuerStage<PK> withNotAfter(@NotNull Instant notAfter);

    @NotNull
    IssuerStage<PK> withDuration(@NotNull Duration duration);
  }

  public interface IssuerStage<PK extends PrivateKey> {

    @NotNull
    PrivateKeyStage<PK> withIssuer(@NotNull String issuer);

    @NotNull
    PrivateKeyStage<PK> withIssuer(@NotNull X509Certificate issuerCert);

    @NotNull
    X509CertificateBuilder.BuildFinal withRootCA(
        @NotNull String dn, @NotNull java.security.KeyPair keyPair, int pathLenConstraint);

    @NotNull
    X509CertificateBuilder.BuildFinal withRootCA(
        @NotNull String dn,
        @NotNull KeyPair<? extends PublicKey, PK> keyPair,
        int pathLenConstraint);
  }

  public interface PrivateKeyStage<PK extends PrivateKey> {

    @NotNull
    PublicKeyStage withSigningKey(@NotNull PK privateKey);
  }

  public interface PublicKeyStage {

    @NotNull
    SubjectStage withPublicKey(@NotNull PublicKey publicKey);
  }

  public interface SubjectStage {

    @NotNull
    ExtensionsStage withSubject(@NotNull String subject);
  }

  public interface ExtensionsStage {

    @NotNull
    X509CertificateBuilder.BuildFinal withExtensions(@NotNull CertificateExtensions extensions);

    @NotNull
    X509CertificateBuilder.BuildFinal withEndEntityExtensions();

    @NotNull
    X509CertificateBuilder.BuildFinal withCertificateAuthorityExtensions(int pathLenConstraint);

    @NotNull
    X509CertificateBuilder.BuildFinal withClientCertificateExtensions();
  }

  public interface BuildFinal {
    @NotNull
    X509CertificateBuilder.BuildFinal withSecureRandom(@NotNull SecureRandom secureRandom);

    @NotNull
    X509Certificate build() throws IOException, GeneralSecurityException;

    BuildChainFinal chain();

    BuildChainFinal chain(
        PrivateKey privateKey, Function<PublicKeyStage, BuildChainFinal> childBuilderFunction);
  }

  public interface BuildChainFinal {
    @NotNull
    X509Certificate[] build() throws IOException, GeneralSecurityException;
  }

  static class InitialStageImpl implements InitialStage {

    @NotNull
    @Override
    public <PK extends PrivateKey> NotBeforeStage<PK> withSignatureAlgorithm(
        @NotNull final String algorithm) {
      return new NotBeforeStageImpl<>(algorithm);
    }

    @NotNull
    @Override
    public NotBeforeStage<RSAPrivateKey> withSHA256withRSA() {
      return new NotBeforeStageImpl<>("SHA256withRSA");
    }

    @NotNull
    @Override
    public NotBeforeStage<RSAPrivateKey> withSHA384withRSA() {
      return new NotBeforeStageImpl<>("SHA384withRSA");
    }

    @NotNull
    @Override
    public NotBeforeStage<RSAPrivateKey> withSHA512withRSA() {
      return new NotBeforeStageImpl<>("SHA512withRSA");
    }

    @NotNull
    @Override
    public NotBeforeStage<ECPrivateKey> withSHA224withECDSA() {
      return new NotBeforeStageImpl<>("SHA224withECDSA");
    }

    @NotNull
    @Override
    public NotBeforeStage<ECPrivateKey> withSHA256withECDSA() {
      return new NotBeforeStageImpl<>("SHA256withECDSA");
    }

    @NotNull
    @Override
    public NotBeforeStage<ECPrivateKey> withSHA384withECDSA() {
      return new NotBeforeStageImpl<>("SHA384withECDSA");
    }

    @NotNull
    @Override
    public NotBeforeStage<ECPrivateKey> withSHA512withECDSA() {
      return new NotBeforeStageImpl<>("SHA512withECDSA");
    }
  }

  static class NotBeforeStageImpl<PK extends PrivateKey> implements NotBeforeStage<PK> {

    private final String algorithm;

    NotBeforeStageImpl(final String algorithm) {
      this.algorithm = algorithm;
    }

    @NotNull
    @Override
    public NotAfterStage<PK> withNotBefore(@NotNull final Instant notBefore) {
      return new NotAfterStageImpl<>(algorithm, notBefore);
    }

    @NotNull
    @Override
    public NotAfterStage<PK> withNotBeforeNow() {
      return new NotAfterStageImpl<>(algorithm, Instant.now());
    }

    @NotNull
    @Override
    public IssuerStage<PK> withDuration(@NotNull final Duration duration) {
      return withDuration(Instant.now(), duration);
    }

    @NotNull
    @Override
    public IssuerStage<PK> withDuration(
        @NotNull final Instant notBefore, @NotNull final Duration duration) {
      return new IssuerStageImpl<>(algorithm, notBefore, notBefore.plus(duration));
    }
  }

  static class NotAfterStageImpl<PK extends PrivateKey> implements NotAfterStage<PK> {

    private final String algorithm;
    private final Instant notBefore;

    NotAfterStageImpl(final String algorithm, final Instant notBefore) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
    }

    @NotNull
    @Override
    public IssuerStage<PK> withNotAfter(@NotNull final Instant notAfter) {
      return new IssuerStageImpl<>(algorithm, notBefore, notAfter);
    }

    @NotNull
    @Override
    public IssuerStage<PK> withDuration(@NotNull final Duration duration) {
      return new IssuerStageImpl<>(algorithm, notBefore, notBefore.plus(duration));
    }
  }

  static class IssuerStageImpl<PK extends PrivateKey> implements IssuerStage<PK> {

    private final String algorithm;
    private final Instant notBefore;
    private final Instant notAfter;

    IssuerStageImpl(final String algorithm, final Instant notBefore, final Instant notAfter) {
      this.algorithm = algorithm;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
    }

    @NotNull
    @Override
    public PrivateKeyStage<PK> withIssuer(@NotNull final String issuer) {
      return new PrivateKeyStageImpl<>(algorithm, notBefore, notAfter, issuer);
    }

    @NotNull
    @Override
    public PrivateKeyStage<PK> withIssuer(@NotNull final X509Certificate issuerCert) {
      return new PrivateKeyStageImpl<>(
          algorithm, notBefore, notAfter, issuerCert.getSubjectDN().getName());
    }

    @NotNull
    @Override
    public X509CertificateBuilder.BuildFinal withRootCA(
        @NotNull final String dn,
        @NotNull final java.security.KeyPair keyPair,
        int pathLenConstraint) {
      return new ExtensionsStageImpl(
              algorithm, notBefore, notAfter, dn, keyPair.getPrivate(), keyPair.getPublic(), dn)
          .withCertificateAuthorityExtensions(pathLenConstraint);
    }

    @NotNull
    @Override
    public X509CertificateBuilder.BuildFinal withRootCA(
        @NotNull final String dn,
        @NotNull final KeyPair<? extends PublicKey, PK> keyPair,
        int pathLenConstraint) {
      return new ExtensionsStageImpl(
              algorithm, notBefore, notAfter, dn, keyPair.getPrivate(), keyPair.getPublic(), dn)
          .withCertificateAuthorityExtensions(pathLenConstraint);
    }
  }

  static class PrivateKeyStageImpl<PK extends PrivateKey> implements PrivateKeyStage<PK> {

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

    @NotNull
    @Override
    public PublicKeyStage withSigningKey(@NotNull final PK privateKey) {
      return new PublicKeyStageImpl(algorithm, notBefore, notAfter, issuer, privateKey);
    }
  }

  static class PublicKeyStageImpl implements PublicKeyStage {

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

    @NotNull
    @Override
    public SubjectStage withPublicKey(@NotNull final PublicKey publicKey) {
      return new SubjectStageImpl(algorithm, notBefore, notAfter, issuer, privateKey, publicKey);
    }
  }

  static class SubjectStageImpl implements SubjectStage {

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

    @NotNull
    @Override
    public ExtensionsStage withSubject(@NotNull final String subject) {
      return new ExtensionsStageImpl(
          algorithm, notBefore, notAfter, issuer, privateKey, publicKey, subject);
    }
  }

  static class ExtensionsStageImpl implements ExtensionsStage {

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

    @NotNull
    @Override
    public X509CertificateBuilder.BuildFinal withExtensions(
        @NotNull final CertificateExtensions extensions) {
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

    @NotNull
    @Override
    public X509CertificateBuilder.BuildFinal withEndEntityExtensions() {
      try {
        final CertificateExtensions extensions = new CertificateExtensions();
        final KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.KEY_ENCIPHERMENT, Boolean.TRUE);
        keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.TRUE);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);
        return new BuildFinalImpl(
            algorithm, subject, issuer, notBefore, notAfter, publicKey, privateKey, extensions);
      } catch (@NotNull final IOException e) {
        throw new IllegalStateException(e);
      }
    }

    @NotNull
    @Override
    public X509CertificateBuilder.BuildFinal withCertificateAuthorityExtensions(
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
      } catch (@NotNull final IOException e) {
        throw new IllegalStateException(e);
      }
    }

    @NotNull
    @Override
    public X509CertificateBuilder.BuildFinal withClientCertificateExtensions() {
      try {
        final CertificateExtensions extensions = new CertificateExtensions();
        final KeyUsageExtension keyUsageExtension = new KeyUsageExtension();
        keyUsageExtension.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.TRUE);
        extensions.set(KeyUsageExtension.NAME, keyUsageExtension);
        return new BuildFinalImpl(
            algorithm, subject, issuer, notBefore, notAfter, publicKey, privateKey, extensions);
      } catch (@NotNull final IOException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  static class BuildFinalImpl implements BuildFinal {

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

    @NotNull
    @Override
    public X509CertificateBuilder.BuildFinal withSecureRandom(
        @NotNull final SecureRandom secureRandom) {
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

    @NotNull
    @Override
    public X509Certificate build() throws GeneralSecurityException {
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
        @SuppressWarnings("sunapi")
        final X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privateKey, algorithm);

        final AlgorithmId algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        final X509CertImpl newCert = new X509CertImpl(info);
        newCert.sign(privateKey, algorithm);
        return newCert;
      } catch (@NotNull final IOException e) {
        throw new GeneralSecurityException(e.getMessage(), e);
      }
    }

    @Override
    public BuildChainFinal chain() {
      return () -> new X509Certificate[] {BuildFinalImpl.this.build()};
    }

    @Override
    public BuildChainFinal chain(
        PrivateKey issuerPrivateKey,
        final Function<PublicKeyStage, BuildChainFinal> childBuilderFunction) {
      return () -> {
        X509Certificate issuerCertificate = BuildFinalImpl.this.build();

        PublicKeyStage publicKeyStage =
            X509CertificateBuilder.builder()
                .withSignatureAlgorithm(algorithm)
                .withNotBefore(notBefore)
                .withNotAfter(notAfter)
                .withIssuer(issuerCertificate)
                .withSigningKey(issuerPrivateKey);

        X509Certificate[] certs = childBuilderFunction.apply(publicKeyStage).build();
        List<X509Certificate> list = new ArrayList<>();
        list.addAll(Arrays.asList(certs));
        list.add(issuerCertificate);
        return list.toArray(new X509Certificate[0]);
      };
    }
  }
}
