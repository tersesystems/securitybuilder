package com.tersesystems.securitybuilder;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import com.tersesystems.securitybuilder.KeyPairCreator.FinalStage;
import com.tersesystems.securitybuilder.X509CertificateCreator.IssuerStage;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

public class X509CertificateCreatorTest {

  @Test
  public void testFunctionalStyle() throws Exception {
    FinalStage<RSAKeyPair> keyPairCreator = KeyPairCreator.creator().withRSA().withKeySize(2048);
    RSAKeyPair rootKeyPair = keyPairCreator.create();
    RSAKeyPair intermediateKeyPair = keyPairCreator.create();
    RSAKeyPair eePair = keyPairCreator.create();

    IssuerStage<RSAPrivateKey> creator =
        X509CertificateCreator.creator().withSHA256withRSA().withDuration(Duration.ofDays(365));

    String issuer = "CN=letsencrypt.derp,O=Root CA";
    X509Certificate[] chain =
        creator
            .withRootCA(issuer, rootKeyPair, 2)
            .chain(
                rootKeyPair.getPrivate(),
                rootCreator ->
                    rootCreator
                        .withPublicKey(intermediateKeyPair.getPublic())
                        .withSubject("OU=intermediate CA")
                        .withCertificateAuthorityExtensions(0)
                        .chain(
                            intermediateKeyPair.getPrivate(),
                            intCreator ->
                                intCreator
                                    .withPublicKey(eePair.getPublic())
                                    .withSubject("CN=tersesystems.com")
                                    .withEndEntityExtensions()
                                    .chain()))
            .create();

    // Check that this passes a certpath validation.
    try {
      final PKIXCertPathValidatorResult result = CertificateChainValidator.validator()
          .withTrustedCertificates(chain[2])
          .withCertificates(Arrays.asList(chain))
          .validate();
      final PublicKey subjectPublicKey = result.getPublicKey();
      assertThat(subjectPublicKey).isEqualTo(eePair.getPublic());
    } catch (final CertPathValidatorException cpve) {
      fail("Cannot test exception", cpve);
    }
  }

  @Test
  public void testCertificate() throws IOException, GeneralSecurityException {

    FinalStage<RSAKeyPair> keyPairCreator = KeyPairCreator.creator().withRSA().withKeySize(2048);
    final RSAKeyPair rootKeyPair = keyPairCreator.create();

    IssuerStage<RSAPrivateKey> creator =
        X509CertificateCreator.creator().withSHA256withRSA().withDuration(Duration.ofDays(365));

    String issuer = "CN=letsencrypt.derp,O=Root CA";

    X509Certificate caCertificate = creator.withRootCA(issuer, rootKeyPair, 2).create();

    final RSAKeyPair intermediateKeyPair = keyPairCreator.create();
    X509Certificate intermediateCaCert =
        creator
            .withIssuer(caCertificate)
            .withSigningKey(rootKeyPair.getPrivate())
            .withPublicKey(intermediateKeyPair.getPublic())
            .withSubject("OU=intermediate CA")
            .withCertificateAuthorityExtensions(0)
            .create();

    final RSAKeyPair eePair = keyPairCreator.create();
    X509Certificate leafCertificate =
        creator
            .withIssuer(intermediateCaCert)
            .withSigningKey(intermediateKeyPair.getPrivate())
            .withPublicKey(eePair.getPublic())
            .withSubject("CN=tersesystems.com")
            .withEndEntityExtensions()
            .create();

    Certificate[] chain = { leafCertificate, intermediateCaCert, caCertificate };

    // Check that this passes a certpath validation.
    try {
      final PKIXCertPathValidatorResult result = CertificateChainValidator.validator()
          .withAnchors(new TrustAnchor(issuer, rootKeyPair.getPublic(), null))
          .withCertificates(chain)
          .validate();
      final PublicKey subjectPublicKey = result.getPublicKey();
      assertThat(subjectPublicKey).isEqualTo(eePair.getPublic());
    } catch (final CertPathValidatorException cpve) {
      fail("Cannot test exception", cpve);
    }
  }

}
