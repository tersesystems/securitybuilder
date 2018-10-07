package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.Test;

public class SecretKeyStoreTest {

  @Test
  void testSize() {
    try {
      final String password = "test";
      final Map<String, ProtectionParameter> passwordMap =
          Collections.singletonMap("alias", new PasswordProtection(password.toCharArray()));
      final SecretKeyStore secretKeyStore = generateSecretKeyStore(passwordMap);

      final int pswdIterations = 65536;
      final int keySize = 256;
      final byte[] saltBytes = {0, 1, 2, 3, 4, 5, 6};

      final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

      final PBEKeySpec spec =
          new PBEKeySpec(password.toCharArray(), saltBytes, pswdIterations, keySize);
      secretKeyStore.put("alias", new SecretKeyEntry(factory.generateSecret(spec)));

      assertThat(secretKeyStore.size()).isEqualTo(1);
    } catch (final KeyStoreException
        | IOException
        | NoSuchAlgorithmException
        | CertificateException
        | InvalidKeySpecException e) {
      fail(e);
    }
  }

  @Test
  void testGet() {
    try {
      final String password = "test";
      final Map<String, ProtectionParameter> passwordMap =
          Collections.singletonMap("alias", new PasswordProtection(password.toCharArray()));
      final SecretKeyStore secretKeyStore = generateSecretKeyStore(passwordMap);

      final int pswdIterations = 65536;
      final int keySize = 256;
      final byte[] saltBytes = {0, 1, 2, 3, 4, 5, 6};

      final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

      final PBEKeySpec spec =
          new PBEKeySpec(password.toCharArray(), saltBytes, pswdIterations, keySize);
      secretKeyStore.put("alias", new SecretKeyEntry(factory.generateSecret(spec)));

      assertThat(secretKeyStore.get("alias")).isExactlyInstanceOf(SecretKeyEntry.class);
    } catch (final KeyStoreException
        | IOException
        | NoSuchAlgorithmException
        | CertificateException
        | InvalidKeySpecException e) {
      fail(e);
    }
  }

  private SecretKeyStore generateSecretKeyStore(Map<String, ProtectionParameter> passwordMap)
      throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException,
          InvalidKeySpecException {
    final KeyStore keyStore = KeyStore.getInstance("JCEKS");
    keyStore.load(null);
    final SecretKeyStore secretKeyStore = SecretKeyStore.create(keyStore, passwordMap::get);
    return secretKeyStore;
  }
}
