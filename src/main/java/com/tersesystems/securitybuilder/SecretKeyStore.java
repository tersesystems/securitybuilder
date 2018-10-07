package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jetbrains.annotations.NotNull;

public interface SecretKeyStore extends Map<String, SecretKeyEntry> {

  @NotNull
  KeyStore getKeyStore();

  @NotNull
  public static SecretKeyStore create(
      @NotNull final KeyStore keyStore,
      @NotNull final Function<String, ProtectionParameter> passwordFunction) {
    final KeyStore.Builder builder =
        PasswordSpecificKeyStoreBuilder.newInstance(keyStore, passwordFunction);
    return create(builder);
  }

  @NotNull
  public static SecretKeyStore create(
      @NotNull final Supplier<KeyStore> keyStoreSupplier,
      @NotNull final Function<String, ProtectionParameter> passwordFunction) {
    final KeyStore.Builder builder =
        PasswordSpecificKeyStoreBuilder.newInstance(keyStoreSupplier, passwordFunction);
    return create(builder);
  }

  @NotNull
  public static SecretKeyStore create(@NotNull final KeyStore.Builder builder) {
    return new SecretKeyStoreImpl(builder);
  }
}
