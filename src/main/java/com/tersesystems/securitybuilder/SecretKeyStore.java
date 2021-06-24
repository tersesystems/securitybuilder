package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/** Provides a Map interface over SecretKeyEntry, using a backing KeyStore. */
public interface SecretKeyStore extends Map<String, SecretKeyEntry> {

  static SecretKeyStore create(
      final KeyStore keyStore, final Function<String, ProtectionParameter> passwordFunction) {
    final KeyStore.Builder builder =
        PasswordSpecificKeyStoreBuilder.newInstance(keyStore, passwordFunction);
    return create(builder);
  }

  static SecretKeyStore create(
      final Supplier<KeyStore> keyStoreSupplier,
      final Function<String, ProtectionParameter> passwordFunction) {
    final KeyStore.Builder builder =
        PasswordSpecificKeyStoreBuilder.newInstance(keyStoreSupplier, passwordFunction);
    return create(builder);
  }

  static SecretKeyStore create(final KeyStore.Builder builder) {
    return new SecretKeyStoreImpl(builder);
  }

  KeyStore getKeyStore();
}
