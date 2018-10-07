package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class KeyManagerKeyStoreBuilder extends PasswordSpecificKeyStoreBuilder {

  protected KeyManagerKeyStoreBuilder(
      @NotNull final Supplier<KeyStore> keyStoreSupplier,
      @NotNull final Function<String, ProtectionParameter> passwordFunction) {
    super(keyStoreSupplier, passwordFunction);
  }

  @Nullable
  @Override
  public ProtectionParameter getProtectionParameter(@NotNull final String alias)
      throws KeyStoreException {
    // alias is lowercased keystore alias with prefixed numbers :-/
    // parse the alias
    final int firstDot = alias.indexOf('.');
    final int secondDot = alias.indexOf('.', firstDot + 1);
    if ((firstDot == -1) || (secondDot == firstDot)) {
      // invalid alias, let's assume that something is asking for the keystore alias
      // that is NOT the key manager, and go with that.
      return super.getProtectionParameter(alias);
    }
    final String keyStoreAlias = alias.substring(secondDot + 1);
    return super.getProtectionParameter(keyStoreAlias);
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

    return new KeyManagerKeyStoreBuilder(keyStoreSupplier, passwordFunction);
  }

  @NotNull
  public static KeyStore.Builder newInstance(
      final KeyStore keyStore, final char[] keyStorePassword) {
    return newInstance(keyStore, new PasswordProtection(keyStorePassword));
  }

  @NotNull
  public static KeyStore.Builder newInstance(
      final KeyStore keyStore, ProtectionParameter protectionParameter) {
    return newInstance(keyStore, alias -> protectionParameter);
  }
}
