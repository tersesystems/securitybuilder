package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.PrivateKeyEntry;
import org.jetbrains.annotations.NotNull;

public class PrivateKeyStoreImpl extends AbstractKeyStore<PrivateKeyEntry>
    implements PrivateKeyStore {

  protected PrivateKeyStoreImpl(@NotNull final Builder builder) {
    super(builder);
  }

  @Override
  public @NotNull KeyStore.Builder getBuilder() {
    return builder;
  }
}
