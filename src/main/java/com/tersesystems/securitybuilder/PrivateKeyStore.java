package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Map;

/**
 * Sets up a private keystore that is set up the way that the default SunX509 keymanager expects --
 * that is, all the private keys have the same password.
 *
 * <p>For keystores that have all individual passwords, i.e. "NewSunX509" keymanager style, we can't
 * use the map interface as noted here.
 */
public interface PrivateKeyStore extends Map<String, PrivateKeyEntry> {

  static PrivateKeyStore create(final KeyStore.Builder builder) {
    return new PrivateKeyStoreImpl(builder);
  }

  static PrivateKeyStore create() {
    return create("".toCharArray());
  }

  static PrivateKeyStore create(final char[] password) {
    return create(new PasswordProtection(password));
  }

  static PrivateKeyStore create(final ProtectionParameter protectionParameter) {
    return create(KeyStoreBuilder.empty(), protectionParameter);
  }

  static PrivateKeyStore create(final KeyStore keyStore, final char[] password) {
    return create(keyStore, new PasswordProtection(password));
  }

  static PrivateKeyStore create(
      final KeyStore keyStore, final ProtectionParameter protectionParameter) {
    return create(KeyManagerKeyStoreBuilder.newInstance(keyStore, protectionParameter));
  }

  static PrivateKeyStore create(
      final String alias, final PrivateKey privateKey, final Certificate... chain) {
    PrivateKeyEntry entry = new PrivateKeyEntry(privateKey, chain);
    return create(alias, entry, new PasswordProtection("".toCharArray()));
  }

  static PrivateKeyStore create(
      final String alias,
      final PrivateKey privateKey,
      final ProtectionParameter protectionParameter,
      final Certificate... chain) {
    PrivateKeyEntry entry = new PrivateKeyEntry(privateKey, chain);
    return create(alias, entry, protectionParameter);
  }

  static PrivateKeyStore create(
      final String alias,
      final PrivateKeyEntry entry,
      final ProtectionParameter protectionParameter) {
    PrivateKeyStore privateKeyStore = create(protectionParameter);
    privateKeyStore.put(alias, entry);
    return privateKeyStore;
  }

  static PrivateKeyStore system() {
    try {
      return create(
          KeyStoreDefaults.getKeyStore(),
          System.getProperty("javax.net.ssl.keyStorePassword", "").toCharArray());
    } catch (final Exception e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  KeyStore getKeyStore();

  KeyStore.Builder getBuilder();
}
