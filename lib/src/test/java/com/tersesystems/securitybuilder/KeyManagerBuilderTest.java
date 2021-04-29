package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.net.ssl.X509ExtendedKeyManager;
import org.junit.jupiter.api.Test;

public class KeyManagerBuilderTest {

  @Test
  public void testKeyManager() {
    try {
      final X509ExtendedKeyManager keyManager =
          KeyManagerBuilder.builder().withNewSunX509().withDefaultKeyStoreAndPassword().build();
      assertThat(keyManager.getPrivateKey("derp")).isNull();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testKeyManagerWithKeyStore() {
    try {
      final KeyStore keyStore = KeyStoreBuilder.empty();
      final X509ExtendedKeyManager keyManager =
          KeyManagerBuilder.builder()
              .withNewSunX509()
              .withKeyStore(keyStore, "".toCharArray())
              .build();
      assertThat(keyManager.getPrivateKey("derp")).isNull();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }
}
