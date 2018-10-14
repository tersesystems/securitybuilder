package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import org.junit.jupiter.api.Test;

public class DifferentPasswordsTest {

  //  @Test
  //  public void testKeyStoreParams() throws GeneralSecurityException, IOException {
  //    KeyStore.Builder getBuilder =
  //        KeyStore.Builder.newInstance(generateStore(), new PasswordProtection("".toCharArray()));
  //    KeyStore getKeyStore = getBuilder.getKeyStore();
  //    PasswordProtection password1Param = new PasswordProtection("password1".toCharArray());
  //    PasswordProtection password2Param = new PasswordProtection("password2".toCharArray());
  //    KeyStore.Entry entry1 = getKeyStore.getEntry("rsaentry", password1Param);
  //    KeyStore.Entry entry2 = getKeyStore.getEntry("dsaentry", password2Param);
  //
  //    assertThat(entry1).isNotNull();
  //    assertThat(entry2).isNotNull();
  //
  //    PasswordProtection entry1Param = (PasswordProtection)
  // getBuilder.getProtectionParameter("rsaentry");
  //    PasswordProtection entry2Param = (PasswordProtection)
  // getBuilder.getProtectionParameter("dsaentry");
  //
  //    // !!! Will always fail because it doesn't get passed in.
  //    assertThat(entry1Param.getPassword()).isEqualTo(password1Param.getPassword());
  //    assertThat(entry2Param.getPassword()).isEqualTo(password2Param.getPassword());
  //  }

  @Test
  public void testWithBuilder() throws GeneralSecurityException, IOException {
    final char[] password1 = "password1".toCharArray();
    final char[] password2 = "password2".toCharArray();
    final Map<String, ProtectionParameter> passwordsMap = new HashMap<>();
    passwordsMap.put("rsaentry", new PasswordProtection(password1));
    passwordsMap.put("dsaentry", new PasswordProtection(password2));

    final KeyStore keyStore = generateStore();
    final KeyStore.Builder builder =
        KeyManagerKeyStoreBuilder.newInstance(keyStore, passwordsMap::get);

    final KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
    kmf.init(new KeyStoreBuilderParameters(builder));
    final X509ExtendedKeyManager keyManager = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];

    final String rsaAlias = keyManager.chooseServerAlias("RSA", null, null);
    assertThat(rsaAlias).contains("rsaentry");
    final PrivateKey rsaPrivateKey = keyManager.getPrivateKey(rsaAlias);
    assertThat(rsaPrivateKey).isNotNull(); // can get password

    final String dsaAlias = keyManager.chooseServerAlias("DSA", null, null);
    assertThat(dsaAlias).contains("dsaentry");
    final PrivateKey dsaPrivateKey = keyManager.getPrivateKey(dsaAlias);
    assertThat(dsaPrivateKey).isNotNull(); // can get password
  }

  private KeyStore generateStore() throws GeneralSecurityException, IOException {
    final KeyPair<RSAPublicKey, RSAPrivateKey> rsaKeyPair =
        KeyPairCreator.creator().withRSA().withKeySize(2048).create();
    final KeyPair<DSAPublicKey, DSAPrivateKey> dsaKeyPair =
        KeyPairCreator.creator().withDSA().withKeySize(1024).create();

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

    final Path privateKeyStorePath = Files.createTempFile(null, ".p12");
    final KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
    pkcs12.load(null);

    final char[] password1 = "password1".toCharArray();
    final char[] password2 = "password2".toCharArray();
    pkcs12.setKeyEntry(
        "rsaEntry", rsaKeyPair.getPrivate(), password1, new Certificate[] {rsaCertificate});
    pkcs12.setKeyEntry(
        "dsaEntry", dsaKeyPair.getPrivate(), password2, new Certificate[] {dsaCertificate});
    pkcs12.store(new FileOutputStream(privateKeyStorePath.toFile()), "".toCharArray());

    return pkcs12;
  }
}
