package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Map;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

/**
 * Sets up a private keystore that is set up the way that the default SunX509 keymanager expects --
 * that is, all the private keys have the same password.
 *
 * <p>For keystores that have all individual passwords, i.e. "NewSunX509" keymanager style, we can't
 * use the map interface as noted here.
 */
public interface PrivateKeyStore extends Map<String, PrivateKeyEntry> {

  @NotNull
  KeyStore getKeyStore();

  @NotNull
  KeyStore.Builder getBuilder();

  @Contract(pure = true)
  @NotNull
  static PrivateKeyStore create() {
    return create("".toCharArray());
  }

  @NotNull
  static PrivateKeyStore create(@NotNull final char[] password) {
    return create(new PasswordProtection(password));
  }

  @NotNull
  static PrivateKeyStore create(@NotNull final ProtectionParameter protectionParameter) {
    return create(KeyStoreBuilder.empty(), protectionParameter);
  }

  @NotNull
  static PrivateKeyStore create(@NotNull final KeyStore keyStore, @NotNull final char[] password) {
    return create(keyStore, new PasswordProtection(password));
  }

  @NotNull
  static PrivateKeyStore create(
      @NotNull final KeyStore keyStore, @NotNull final ProtectionParameter protectionParameter) {
    return create(KeyManagerKeyStoreBuilder.newInstance(keyStore, protectionParameter));
  }

  @NotNull
  static PrivateKeyStore create(@NotNull final KeyStore.Builder builder) {
    return new PrivateKeyStoreImpl(builder);
  }

  @NotNull
  static PrivateKeyStore create(
      @NotNull final String alias,
      @NotNull final PrivateKey privateKey,
      @NotNull final Certificate... chain) {
    PrivateKeyEntry entry = new PrivateKeyEntry(privateKey, chain);
    return create(alias, entry, new PasswordProtection("".toCharArray()));
  }

  @NotNull
  static PrivateKeyStore create(
      @NotNull final String alias,
      @NotNull final PrivateKey privateKey,
      @NotNull final ProtectionParameter protectionParameter,
      @NotNull final Certificate... chain) {
    PrivateKeyEntry entry = new PrivateKeyEntry(privateKey, chain);
    return create(alias, entry, protectionParameter);
  }

  @NotNull
  static PrivateKeyStore create(
      @NotNull final String alias,
      @NotNull final PrivateKeyEntry entry,
      @NotNull final ProtectionParameter protectionParameter) {
    PrivateKeyStore privateKeyStore = create(protectionParameter);
    privateKeyStore.put(alias, entry);
    return privateKeyStore;
  }

  @NotNull
  static PrivateKeyStore system() {
    try {
      return create(
          KeyStoreDefaults.getKeyStore(),
          System.getProperty("javax.net.ssl.keyStorePassword", "").toCharArray());
    } catch (final Exception e) {
      throw new RuntimeKeyStoreException(e);
    }
  }
}
