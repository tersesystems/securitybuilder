package com.tersesystems.securitybuilder;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import com.tersesystems.securitybuilder.KeyPairCreator.FinalStage;
import com.tersesystems.securitybuilder.X509CertificateCreator.IssuerStage;
import java.io.IOException;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

public class X509CertificateCreatorTest {

  @Test
  public void testFunctionalStyle() throws Exception {

    FinalStage<RSAKeyPair> keyPairCreator = KeyPairCreator.creator().withRSA().withKeySize(2048);
    final RSAKeyPair rootKeyPair = keyPairCreator.create();
    final RSAKeyPair intermediateKeyPair = keyPairCreator.create();
    final RSAKeyPair eePair = keyPairCreator.create();

    IssuerStage<RSAPrivateKey> builder =
        X509CertificateCreator.creator().withSHA256withRSA().withDuration(Duration.ofDays(365));

    String issuer = "CN=letsencrypt.derp,O=Root CA";
    X509Certificate[] chain =
        builder
            .withRootCA(issuer, rootKeyPair, 2)
            .chain(
                rootKeyPair.getPrivate(),
                rootBuilder ->
                    rootBuilder
                        .withPublicKey(intermediateKeyPair.getPublic())
                        .withSubject("OU=intermediate CA")
                        .withCertificateAuthorityExtensions(0)
                        .chain(
                            intermediateKeyPair.getPrivate(),
                            intBuilder ->
                                intBuilder
                                    .withPublicKey(eePair.getPublic())
                                    .withSubject("CN=tersesystems.com")
                                    .withEndEntityExtensions()
                                    .chain()))
            .create();
    //    try {
    //      final TrustAnchor anchor =
    //          new TrustAnchor(issuer, rootKeyPair.getPublic(), null);
    //      final PKIXCertPathValidatorResult result = validateChain(privateKeyStore, anchor);
    //      final PublicKey subjectPublicKey = result.getPublicKey();
    //      assertThat(subjectPublicKey).isEqualTo(eePair.getPublic());
    //    } catch (final CertPathValidatorException cpve) {
    //      fail("Cannot test exception", cpve);
    //    }

    PrivateKeyStore privateKeyStore =
        PrivateKeyStore.create("tersesystems.com", eePair.getPrivate(), chain);
    TrustStore trustStore = TrustStore.create(singletonList(chain[2]), cert -> "letsencrypt.derp");

    SSLContext sslContext =
        SSLContextBuilder.builder()
            .withTLS()
            .withKeyManager(
                KeyManagerBuilder.builder()
                    .withSunX509()
                    .withPrivateKeyStore(privateKeyStore)
                    .build())
            .withTrustManager(
                TrustManagerBuilder.builder()
                    .withDefaultAlgorithm()
                    .withTrustStore(trustStore)
                    .build())
            .build();
    assertThat(sslContext).isNotNull();
  }

  @Test
  public void testCertificate() throws IOException, GeneralSecurityException {

    FinalStage<RSAKeyPair> keyPairCreator = KeyPairCreator.creator().withRSA().withKeySize(2048);
    final RSAKeyPair rootKeyPair = keyPairCreator.create();

    IssuerStage<RSAPrivateKey> creator =
        X509CertificateCreator.creator().withSHA256withRSA().withDuration(Duration.ofDays(365));

    String issuer = "CN=letsencrypt.derp,O=Root CA";

    X509Certificate caCertificate = creator.withRootCA(issuer, rootKeyPair, 2).build();

    final RSAKeyPair intermediateKeyPair = keyPairCreator.create();
    X509Certificate intermediateCaCert =
        creator
            .withIssuer(caCertificate)
            .withSigningKey(rootKeyPair.getPrivate())
            .withPublicKey(intermediateKeyPair.getPublic())
            .withSubject("OU=intermediate CA")
            .withCertificateAuthorityExtensions(0)
            .build();

    final RSAKeyPair eePair = keyPairCreator.create();
    X509Certificate leafCertificate =
        creator
            .withIssuer(intermediateCaCert)
            .withSigningKey(intermediateKeyPair.getPrivate())
            .withPublicKey(eePair.getPublic())
            .withSubject("CN=tersesystems.com")
            .withEndEntityExtensions()
            .build();

    PrivateKeyStore privateKeyStore =
        PrivateKeyStore.create(
            "alias", eePair.getPrivate(), leafCertificate, intermediateCaCert, caCertificate);

    // Check that this passes a certpath validation.
    try {
      final TrustAnchor anchor = new TrustAnchor(issuer, rootKeyPair.getPublic(), null);
      final PKIXCertPathValidatorResult result = validateChain(privateKeyStore, anchor);
      final PublicKey subjectPublicKey = result.getPublicKey();
      assertThat(subjectPublicKey).isEqualTo(eePair.getPublic());
    } catch (final CertPathValidatorException cpve) {
      fail("Cannot test exception", cpve);
    }
  }

  PKIXCertPathValidatorResult validateChain(PrivateKeyStore privateKeyStore, TrustAnchor anchor)
      throws CertificateException, NoSuchAlgorithmException, CertPathValidatorException,
          InvalidAlgorithmParameterException {
    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    final Certificate[] chain = privateKeyStore.get("alias").getCertificateChain();
    final CertPath certPath =
        certificateFactory.generateCertPath(Arrays.asList(chain[0], chain[1]));

    final CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
    final PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
    params.setRevocationEnabled(false);

    final SimpleChecker sc = new SimpleChecker();
    params.addCertPathChecker(sc);

    final PKIXCertPathValidatorResult result =
        (PKIXCertPathValidatorResult) cpv.validate(certPath, params);
    return result;
  }

  private static class SimpleChecker extends PKIXCertPathChecker {

    private static final Set<CryptoPrimitive> SIGNATURE_PRIMITIVE_SET =
        EnumSet.of(CryptoPrimitive.SIGNATURE);

    public void init(final boolean forward) throws CertPathValidatorException {}

    public boolean isForwardCheckingSupported() {
      return true;
    }

    public Set<String> getSupportedExtensions() {
      return Collections.emptySet();
    }

    public void check(final Certificate cert, final Collection<String> unresolvedCritExts)
        throws CertPathValidatorException {
      final X509Certificate c = (X509Certificate) cert;
      final String sa = c.getSigAlgName();
      final Key key = c.getPublicKey();

      final AlgorithmConstraints constraints = new SimpleConstraints();

      if (!constraints.permits(SIGNATURE_PRIMITIVE_SET, sa, null)) {
        throw new CertPathValidatorException("Forbidden algorithm: " + sa);
      }

      if (!constraints.permits(SIGNATURE_PRIMITIVE_SET, key)) {
        throw new CertPathValidatorException("Forbidden key: " + key);
      }
    }
  }

  private static class SimpleConstraints implements AlgorithmConstraints {

    public boolean permits(
        final Set<CryptoPrimitive> primitives,
        final String algorithm,
        final AlgorithmParameters parameters) {
      return permits(primitives, algorithm, null, parameters);
    }

    public boolean permits(final Set<CryptoPrimitive> primitives, final Key key) {
      return permits(primitives, null, key, null);
    }

    public boolean permits(
        final Set<CryptoPrimitive> primitives,
        String algorithm,
        final Key key,
        final AlgorithmParameters parameters) {
      if (algorithm == null) {
        algorithm = key.getAlgorithm();
      }

      if (!algorithm.contains("RSA")) {
        return false;
      }

      if (key != null) {
        final RSAKey rsaKey = (RSAKey) key;
        final int size = rsaKey.getModulus().bitLength();
        return size >= 2048;
      }

      return true;
    }
  }
}
