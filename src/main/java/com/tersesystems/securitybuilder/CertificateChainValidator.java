package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Validates a certificate chain using CertPathValidator.
 */
public class CertificateChainValidator {

  public interface InitialStage {

    CertificatesStage withTrustedCertificates(Certificate... certificates);

    CertificatesStage withTrustStore(TrustStore trustStore);

    CertificatesStage withKeyStore(KeyStore keyStore);

    CertificatesStage withAnchors(TrustAnchor... anchors);

    CertificatesStage withAnchors(Set<TrustAnchor> anchors);

    CertificatesStage withAnchors(Supplier<Set<TrustAnchor>> anchors);
  }

  public interface CertificatesStage {

    FinalStage withCertificates(Certificate[] certificates);

    FinalStage withCertificates(List<? extends Certificate> certificates);

    FinalStage withCertificates(Supplier<List<? extends Certificate>> certificates);
  }

  public interface FinalStage {

    PKIXCertPathValidatorResult validate() throws GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {

    @Override
    public CertificatesStage withTrustedCertificates(final Certificate... certificates) {
      return new CertificatesStageImpl(() -> Arrays.stream(certificates)
          .map(certificate -> new TrustAnchor((X509Certificate) certificate, null))
          .collect(Collectors.toSet()));
    }

    @Override
    public CertificatesStage withTrustStore(final TrustStore trustStore) {
      return new CertificatesStageImpl(() -> trustStore.entrySet().stream().map(entry -> {
        Certificate certificate = entry.getValue().getTrustedCertificate();
        return new TrustAnchor((X509Certificate) certificate, null);
      }).collect(Collectors.toSet()));
    }

    @Override
    public CertificatesStage withKeyStore(final KeyStore keyStore) {
      return withTrustStore(TrustStore.create(keyStore));
    }

    @Override
    public CertificatesStage withAnchors(final TrustAnchor... anchors) {
      return new CertificatesStageImpl(() -> Arrays.stream(anchors).collect(Collectors.toSet()));
    }

    @Override
    public CertificatesStage withAnchors(final Set<TrustAnchor> anchors) {
      return new CertificatesStageImpl(() -> anchors);
    }

    @Override
    public CertificatesStage withAnchors(final Supplier<Set<TrustAnchor>> supplier) {
      return new CertificatesStageImpl(supplier);
    }
  }

  private static class CertificatesStageImpl implements CertificatesStage {

    private final Supplier<Set<TrustAnchor>> anchorsSupplier;

    CertificatesStageImpl(final Supplier<Set<TrustAnchor>> anchorsSupplier) {
      this.anchorsSupplier = anchorsSupplier;
    }

    @Override
    public FinalStage withCertificates(final Certificate[] certificates) {
      return new FinalStageImpl(anchorsSupplier, () -> Arrays.asList(certificates));
    }

    @Override
    public FinalStage withCertificates(final List<? extends Certificate> certificates) {
      return new FinalStageImpl(anchorsSupplier, () -> certificates);
    }

    @Override
    public FinalStage withCertificates(final Supplier<List<? extends Certificate>> supplier) {
      return new FinalStageImpl(anchorsSupplier, supplier);
    }
  }

  private static class FinalStageImpl implements FinalStage {

    private final Supplier<Set<TrustAnchor>> anchorsSupplier;
    private final Supplier<List<? extends Certificate>> certSupplier;

    private FinalStageImpl(
        final Supplier<Set<TrustAnchor>> anchorsSupplier,
        final Supplier<List<? extends Certificate>> certSupplier) {
      this.anchorsSupplier = anchorsSupplier;
      this.certSupplier = certSupplier;
    }

    @Override
    public PKIXCertPathValidatorResult validate() throws GeneralSecurityException {
      final CertPathValidator cpv = CertPathValidator.getInstance("PKIX");

      final PKIXParameters params = new PKIXParameters(anchorsSupplier.get());
      params.setRevocationEnabled(false);
      //params.addCertPathChecker(sc);

      final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      List<? extends Certificate> certificates = certSupplier.get();
      final CertPath certPath = certificateFactory
          .generateCertPath(certificates.subList(0, certificates.size() - 1));
      return (PKIXCertPathValidatorResult) cpv.validate(certPath, params);
    }
  }

  public static InitialStage validator() {
    return new InitialStageImpl();
  }
}
