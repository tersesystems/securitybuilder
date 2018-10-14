package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Validates a certificate chain using CertPathValidator.
 */
public class CertificateChainValidator {

  public interface InitialStage {

    CertificatesStage withAnchor(TrustAnchor anchor);

    CertificatesStage withAnchors(Set<TrustAnchor> anchors);

    CertificatesStage withAnchors(Supplier<Set<TrustAnchor>> anchors);
  }

  public interface CertificatesStage {
    FinalStage withCertificates(Certificate[] certificates);
    FinalStage withCertificates(List<Certificate> certificates);
    FinalStage withCertificates(Supplier<List<Certificate>> certificates);
  }

  public interface FinalStage {

    PKIXCertPathValidatorResult validate()
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateException, CertPathValidatorException, GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {

    @Override
    public CertificatesStage withAnchor(final TrustAnchor anchor) {
      return new CertificatesStageImpl(() -> Collections.singleton(anchor));
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
    public FinalStage withCertificates(final List<Certificate> certificates) {
      return new FinalStageImpl(anchorsSupplier, () -> certificates);
    }

    @Override
    public FinalStage withCertificates(final Supplier<List<Certificate>> supplier) {
      return new FinalStageImpl(anchorsSupplier, supplier);
    }
  }

  private static class FinalStageImpl implements FinalStage {

    private final Supplier<Set<TrustAnchor>> anchorsSupplier;
    private final Supplier<List<Certificate>> certSupplier;

    private FinalStageImpl(
        final Supplier<Set<TrustAnchor>> anchorsSupplier,
        final Supplier<List<Certificate>> certSupplier) {
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
      List<Certificate> certificates = certSupplier.get();
      final CertPath certPath = certificateFactory.generateCertPath(certificates.subList(0, certificates.size() - 1));
      return (PKIXCertPathValidatorResult) cpv.validate(certPath, params);
    }
  }

  public static InitialStage validator() {
    return new InitialStageImpl();
  }
}
