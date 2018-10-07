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

class TrustStoreTest {

  @Test
  void testSize() {
    try {
      final KeyStore keyStore = generateStore();
      final TrustStore trustStore = TrustStore.create(keyStore);

      final RSAKeyPair rsaKeyPair = KeyPairBuilder.builder().withRSA().withKeySize(2048).build();
      final DSAKeyPair dsaKeyPair = KeyPairBuilder.builder().withDSA().withKeySize(1024).build();

      final X509Certificate rsaCertificate =
          X509CertificateBuilder.builder()
              .withSHA256withRSA()
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", rsaKeyPair, 2)
              .build();

      final X509Certificate dsaCertificate =
          X509CertificateBuilder.builder()
              .withSignatureAlgorithm("SHA256withDSA")
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", dsaKeyPair.getKeyPair(), 2)
              .build();

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
