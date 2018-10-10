package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

public class PasswordSpecificKeyStoreBuilder extends KeyStore.Builder {

  private final Supplier<KeyStore> keyStoreSupplier;
  private final Function<String, ProtectionParameter> passwordFunction;

  protected PasswordSpecificKeyStoreBuilder(
      final Supplier<KeyStore> keyStoreSupplier,
      final Function<String, ProtectionParameter> passwordFunction) {
    Objects.requireNonNull(keyStoreSupplier);
    Objects.requireNonNull(passwordFunction);
    this.keyStoreSupplier = keyStoreSupplier;
    this.passwordFunction = passwordFunction;
  }

  public static KeyStore.Builder newInstance(
      final KeyStore keyStore,
      final Function<String, ProtectionParameter> passwordFunction) {
    Objects.requireNonNull(keyStore);
    Objects.requireNonNull(passwordFunction);

    return newInstance(() -> keyStore, passwordFunction);
  }

  public static KeyStore.Builder newInstance(
      final Supplier<KeyStore> keyStoreSupplier,
      final Function<String, ProtectionParameter> passwordFunction) {
    Objects.requireNonNull(keyStoreSupplier);
    Objects.requireNonNull(passwordFunction);

    return new PasswordSpecificKeyStoreBuilder(keyStoreSupplier, passwordFunction);
  }

  @Override
  public KeyStore getKeyStore() throws KeyStoreException {
    return keyStoreSupplier.get();
  }

  @Override
  public ProtectionParameter getProtectionParameter(final String alias) throws KeyStoreException {
    Objects.requireNonNull(alias);
    return passwordFunction.apply(alias);
  }
}
