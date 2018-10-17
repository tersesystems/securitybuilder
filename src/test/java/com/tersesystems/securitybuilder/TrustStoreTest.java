package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.cert.X509Certificate;
import java.time.Duration;
import org.junit.jupiter.api.Test;

public class TrustStoreTest {

  @Test
  public void testSize() {
    try {
      final KeyStore keyStore = generateStore();
      final TrustStore trustStore = TrustStore.create(keyStore);

      final RSAKeyPair rsaKeyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).create();
      final DSAKeyPair dsaKeyPair = KeyPairCreator.creator().withDSA().withKeySize(1024).create();

      final X509Certificate rsaCertificate =
          X509CertificateCreator.creator()
              .withSHA256withRSA()
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", rsaKeyPair, 2)
              .create();

      final X509Certificate dsaCertificate =
          X509CertificateCreator.creator()
              .withSignatureAlgorithm("SHA256withDSA")
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", dsaKeyPair.getKeyPair(), 2)
              .create();

      trustStore.put("rsaentry", new TrustedCertificateEntry(rsaCertificate));
      trustStore.put("dsaentry", new TrustedCertificateEntry(dsaCertificate));

      assertThat(trustStore.size()).isEqualTo(2);
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }

  private KeyStore generateStore() throws GeneralSecurityException, IOException {

    final Path privateKeyStorePath = Files.createTempFile(null, ".p12");
    final KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
    pkcs12.load(null);

    return pkcs12;
  }
}
