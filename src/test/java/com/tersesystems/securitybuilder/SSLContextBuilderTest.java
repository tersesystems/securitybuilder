package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.fail;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.Test;

public class SSLContextBuilderTest {

  @Test
  public void testSSLContextBuilderWithTLS() {
    try {
      final SSLContext sslContext = SSLContextBuilder.builder().withTLS().build();
      sslContext.createSSLEngine();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testSSLContextBuilderWithTLSAndKeyManager() {
    try {
      final X509ExtendedKeyManager km =
          KeyManagerBuilder.builder().withNewSunX509().withDefaultKeyStoreAndPassword().build();

      final SSLContext sslContext =
          SSLContextBuilder.builder().withTLS().withKeyManager(km).build();
      sslContext.createSSLEngine();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testSSLContextBuilderWithTLSAndTrustManager() {
    try {
      final X509ExtendedTrustManager trustManager =
          TrustManagerBuilder.builder().withDefaultAlgorithm().withDefaultKeystore().build();
      final SSLContext sslContext =
          SSLContextBuilder.builder().withTLS().withTrustManager(trustManager).build();
      sslContext.createSSLEngine();
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testSSLContextBuilderWithTLSAndSecureRandom() {
    try {
      final X509ExtendedTrustManager trustManager =
          TrustManagerBuilder.builder().withDefaultAlgorithm().withDefaultKeystore().build();
      final SSLContext sslContext =
          SSLContextBuilder.builder().withTLS().withSecureRandom(new SecureRandom()).build();
      sslContext.createSSLEngine();
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }
}
