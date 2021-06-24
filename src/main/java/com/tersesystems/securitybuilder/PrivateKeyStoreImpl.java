package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.Objects;

public class PrivateKeyStoreImpl extends AbstractKeyStore<PrivateKeyEntry>
    implements PrivateKeyStore {

  protected PrivateKeyStoreImpl(final Builder builder) {
    super(builder);
  }

  public PrivateKeyEntry get(final Object key) {
    if (key instanceof String) {
      final String alias = (String) key;
      Objects.requireNonNull(alias, "Null alias!");
      try {
        final KeyStore keyStore = getKeyStore();
        // If we have a CRT key, there's no chain attached and JDK 11 will error out.
        // So there's literally a key but no entry.
        if (keyStore.getCertificateChain(alias) == null) {
          String msg = "No entry available because there is no certificate chain for " + alias;
          final KeyStoreException e = new KeyStoreException(msg);
          throw new RuntimeKeyStoreException(e);
        }
        return (PrivateKeyEntry) keyStore.getEntry(alias, protectionParameter(alias));
      } catch (
              final NoSuchAlgorithmException
                      | UnrecoverableEntryException
                      | KeyStoreException e) {
        throw new RuntimeKeyStoreException(e);
      }
    }
    return null;
  }

  @Override
  public KeyStore.Builder getBuilder() {
    return builder;
  }

  @Override
  public String toString() {
    return String.format("PrivateKeyStoreImpl(size = %s)", size());
  }
}
