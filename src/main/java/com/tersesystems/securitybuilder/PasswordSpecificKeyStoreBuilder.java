package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class PasswordSpecificKeyStoreBuilder extends KeyStore.Builder {

  @NotNull private final Supplier<KeyStore> keyStoreSupplier;
  @NotNull private final Function<String, ProtectionParameter> passwordFunction;

  protected PasswordSpecificKeyStoreBuilder(
      @NotNull final Supplier<KeyStore> keyStoreSupplier,
      @NotNull final Function<String, ProtectionParameter> passwordFunction) {
    Objects.requireNonNull(keyStoreSupplier);
    Objects.requireNonNull(passwordFunction);
    this.keyStoreSupplier = keyStoreSupplier;
    this.passwordFunction = passwordFunction;
  }

  @Override
  public KeyStore getKeyStore() throws KeyStoreException {
    return keyStoreSupplier.get();
  }

  @Nullable
  @Override
  public ProtectionParameter getProtectionParameter(final String alias) throws KeyStoreException {
    Objects.requireNonNull(alias);
    return passwordFunction.apply(alias);
  }

  @NotNull
  public static KeyStore.Builder newInstance(
      @NotNull final KeyStore keyStore,
      @NotNull final Function<String, ProtectionParameter> passwordFunction) {
    Objects.requireNonNull(keyStore);
    Objects.requireNonNull(passwordFunction);

    return newInstance(() -> keyStore, passwordFunction);
  }

  @NotNull
  public static KeyStore.Builder newInstance(
      @NotNull final Supplier<KeyStore> keyStoreSupplier,
      @NotNull final Function<String, ProtectionParameter> passwordFunction) {
    Objects.requireNonNull(keyStoreSupplier);
    Objects.requireNonNull(passwordFunction);

    return new PasswordSpecificKeyStoreBuilder(keyStoreSupplier, passwordFunction);
  }
}
