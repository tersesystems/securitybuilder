package com.tersesystems.securitybuilder;

import java.security.KeyStore.Builder;
import java.security.KeyStore.SecretKeyEntry;

public class SecretKeyStoreImpl extends AbstractKeyStore<SecretKeyEntry> implements SecretKeyStore {

  protected SecretKeyStoreImpl(final Builder builder) {
    super(builder);
  }
}
