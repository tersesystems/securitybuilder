package com.tersesystems.securitybuilder;

import java.security.KeyStore.Builder;
import java.security.KeyStore.SecretKeyEntry;
import org.jetbrains.annotations.NotNull;

public class SecretKeyStoreImpl extends AbstractKeyStore<SecretKeyEntry> implements SecretKeyStore {

  protected SecretKeyStoreImpl(@NotNull final Builder builder) {
    super(builder);
  }
}
