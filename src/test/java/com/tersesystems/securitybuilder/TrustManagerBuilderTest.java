package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyStore;
import java.security.cert.*;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.Test;

class TrustManagerBuilderTest {

  @Test
  void builderWithDefaults() throws Exception {
    final X509ExtendedTrustManager trustManager =
        TrustManagerBuilder.builder().withDefaultAlgorithm().withDefaultKeystore().build();
    assertThat(trustManager).isNotNull();
    assertThat(trustManager.getAcceptedIssuers()).isNotEmpty();
  }

  @Test
  void builderWithKeyStore() throws Exception {
    final KeyStore keyStore = KeyStoreBuilder.empty();
    final X509ExtendedTrustManager trustManager =
        TrustManagerBuilder.builder().withDefaultAlgorithm().withKeyStore(keyStore).build();
    assertThat(trustManager.getAcceptedIssuers()).isEmpty();
  }

  @Test
  void builderWithPKIXParameters() throws Exception {
    final X509Certificate certificate =
        CertificateBuilder.builder()
            .withX509()
            .withResource("playframework.pem", this.getClass().getClassLoader())
            .build();
    final KeyStore keyStore = KeyStoreBuilder.empty();
    keyStore.setCertificateEntry("root", certificate);
    final PKIXBuilderParameters params =
        new PKIXBuilderParameters(keyStore, new X509CertSelector());
    final X509ExtendedTrustManager trustManager =
        TrustManagerBuilder.builder()
            .withDefaultAlgorithm()
            .withPKIXBuilderParameters(params)
            .build();
    assertThat(trustManager.getAcceptedIssuers()).contains(certificate);
  }
}
