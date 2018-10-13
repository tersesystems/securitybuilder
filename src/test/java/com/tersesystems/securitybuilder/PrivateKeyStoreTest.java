package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.Properties;
import org.junit.jupiter.api.Test;

public class PrivateKeyStoreTest {

  @Test
  public void testSystem() {
    try {
      final char[] password = "".toCharArray();
      final KeyStore keyStore = generateStore(password);
      final Path tempPath = Files.createTempFile(null, null);
      keyStore.store(new FileOutputStream(tempPath.toFile()), password);

      final Properties properties = new Properties();
      properties.setProperty("javax.net.ssl.getKeyStore", tempPath.toAbsolutePath().toString());
      properties.setProperty("javax.net.ssl.keyStoreType", KeyStore.getDefaultType());
      properties.setProperty("javax.net.ssl.keyStorePassword", new String(password));
      System.setProperties(properties);

      final PrivateKeyStore systemPrivateKeyStore = PrivateKeyStore.system();
      assertThat(systemPrivateKeyStore.get("rsaentry")).isNotNull();
    } catch (final Exception e) {
      e.printStackTrace();
      fail(e.getMessage());
    }
  }

  @Test
  public void testControlStore() {
    try {
      final char[] password = "".toCharArray();
      final KeyStore keyStore = generateStore(password);
      final PrivateKeyStore privateKeyStore = PrivateKeyStore.create(keyStore, password);

      assertThat(privateKeyStore.size()).isEqualTo(2);
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }

  @Test
  public void testSize() {
    try {
      final char[] password = "".toCharArray();
      final KeyStore keyStore = generateStore(password);
      final PrivateKeyStore privateKeyStore = PrivateKeyStore.create(keyStore, password);

      assertThat(privateKeyStore.size()).isEqualTo(2);
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }

  @Test
  public void testEntrySet() {
    try {
      final char[] password = "".toCharArray();
      final KeyStore keyStore = generateStore(password);
      final PrivateKeyStore privateKeyStore = PrivateKeyStore.create(keyStore, password);

      assertThat(privateKeyStore.entrySet().stream().findFirst()).isNotEmpty();
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }

  @Test
  public void testAdd() {
    try {
      final char[] password = "".toCharArray();
      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null);
      final PrivateKeyStore privateKeyStore = PrivateKeyStore.create(keyStore, password);
      final RSAKeyPair rsaKeyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).create();

      final X509Certificate rsaCertificate =
          X509CertificateCreator.creator()
              .withSHA256withRSA()
              .withNotBeforeNow()
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", rsaKeyPair, 2)
              .build();
      final PrivateKeyEntry entry =
          new PrivateKeyEntry(rsaKeyPair.getPrivate(), new Certificate[] {rsaCertificate});
      privateKeyStore.put("alias1", entry);

      // PrivateKey doesn't override equals!
      assertThat(Arrays.equals(privateKeyStore.get("alias1").getPrivateKey().getEncoded(), (entry.getPrivateKey().getEncoded()))).isTrue();
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }

  private KeyStore generateStore(final char[] password)
      throws GeneralSecurityException, IOException {
    final RSAKeyPair rsaKeyPair = (KeyPairCreator.creator().withRSA().withKeySize(2048).create());
    final DSAKeyPair dsaKeyPair = (KeyPairCreator.creator().withDSA().withKeySize(1024).create());

    final X509Certificate rsaCertificate =
        X509CertificateCreator.creator()
            .withSHA256withRSA()
            .withDuration(Duration.ofDays(365))
            .withRootCA("CN=example.com", rsaKeyPair, 2)
            .build();

    final X509Certificate dsaCertificate =
        X509CertificateCreator.creator()
            .<DSAPrivateKey>withSignatureAlgorithm("SHA256withDSA")
            .withDuration(Duration.ofDays(365))
            .withRootCA("CN=example.com", dsaKeyPair, 2)
            .build();

    final KeyStore pkcs12 = KeyStore.getInstance(KeyStore.getDefaultType());
    pkcs12.load(null);

    pkcs12.setKeyEntry(
        "rsaentry", rsaKeyPair.getPrivate(), password, new Certificate[] {rsaCertificate});
    pkcs12.setKeyEntry(
        "dsaentry", dsaKeyPair.getPrivate(), password, new Certificate[] {dsaCertificate});

    return pkcs12;
  }
}
