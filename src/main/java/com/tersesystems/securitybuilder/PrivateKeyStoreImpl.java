package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.PrivateKeyEntry;

public class PrivateKeyStoreImpl extends AbstractKeyStore<PrivateKeyEntry>
    implements PrivateKeyStore {

  protected PrivateKeyStoreImpl(final Builder builder) {
    super(builder);
  }

  @Override
  public KeyStore.Builder getBuilder() {
    return builder;
  }
}
