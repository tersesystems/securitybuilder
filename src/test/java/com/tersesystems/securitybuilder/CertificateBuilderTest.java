package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

public class CertificateBuilderTest {

  @Test
  public void testX509Certificate() {
    final InputStream inputStream = getClass().getResourceAsStream("/playframework.pem");
    try {
      final X509Certificate x509Certificate =
          CertificateBuilder.builder().withX509().withInputStream(inputStream).build();
      assertThat(x509Certificate.getSigAlgName()).isEqualTo("SHA256withECDSA");
    } catch (final CertificateException e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testCertificateWithInputStream() {
    final InputStream inputStream = getClass().getResourceAsStream("/playframework.pem");
    try {
      final Certificate certificate =
          CertificateBuilder.builder().withAlgorithm("X.509").withInputStream(inputStream).build();
      assertThat(certificate.getType()).isEqualTo("X.509");
    } catch (final CertificateException e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testCertificateWithReader() {
    final InputStream inputStream = getClass().getResourceAsStream("/playframework.pem");
    try {
      final Certificate certificate =
          CertificateBuilder.builder()
              .withAlgorithm("X.509")
              .withReader(new InputStreamReader(inputStream))
              .build();
      assertThat(certificate.getType()).isEqualTo("X.509");
    } catch (final CertificateException e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testCertificateWithResource() {
    try {
      final Certificate certificate =
          CertificateBuilder.builder()
              .withAlgorithm("X.509")
              .withResource("playframework.pem", ClassLoader.getSystemClassLoader())
              .build();
      assertThat(certificate.getType()).isEqualTo("X.509");
    } catch (final CertificateException e) {
      fail(e.getMessage(), e);
    }
  }
}
