package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/** A keystore containing trusted certificate entries. */
public class TrustStoreImpl extends AbstractKeyStore<TrustedCertificateEntry>
    implements TrustStore {

  protected TrustStoreImpl(@NotNull final Builder builder) {
    super(builder);
  }

  @NotNull
  public TrustedCertificateEntry putCertificate(@NotNull String key, @NotNull Certificate certificate) {
    return put(key, new KeyStore.TrustedCertificateEntry(certificate));
  }

  @NotNull
  @Override
  public Optional<String> getCertificateAlias(@NotNull final Certificate certificate)
      throws RuntimeKeyStoreException {
    try {
      return Optional.ofNullable(getKeyStore().getCertificateAlias(certificate));
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  @Override
  public KeyStore.TrustedCertificateEntry put(
      final String alias, final KeyStore.TrustedCertificateEntry value) {
    try {
      // Override from the Abstract as the protection parameter is always nul here.
      getKeyStore().setEntry(alias, value, null);
      return value;
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  class TrustStoreEntry implements Entry<String, KeyStore.TrustedCertificateEntry> {

    private final String alias;

    TrustStoreEntry(final String alias) {
      this.alias = alias;
    }

    @Override
    public String getKey() {
      return alias;
    }

    @NotNull
    @Override
    public KeyStore.TrustedCertificateEntry getValue() {
      try {
        return (KeyStore.TrustedCertificateEntry) getKeyStore().getEntry(alias, null);
      } catch (@NotNull final Exception e) {
        throw new RuntimeKeyStoreException(e);
      }
    }

    @NotNull
    @Override
    public KeyStore.TrustedCertificateEntry setValue(
        @NotNull final KeyStore.TrustedCertificateEntry value) {
      try {
        getKeyStore().setEntry(alias, value, null);
        return value;
      } catch (@NotNull final KeyStoreException e) {
        throw new RuntimeKeyStoreException(e);
      }
    }

    @Override
    public boolean equals(@Nullable final Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      final TrustStoreEntry that = (TrustStoreEntry) o;
      final TrustedCertificateEntry thisCertEntry = getValue();
      final TrustedCertificateEntry thatCertEntry = that.getValue();
      return Objects.equals(alias, that.alias)
          && Objects.equals(
              thisCertEntry.getTrustedCertificate(), thatCertEntry.getTrustedCertificate())
          && Objects.equals(thisCertEntry.getAttributes(), thatCertEntry.getAttributes());
    }

    @Override
    public int hashCode() {
      return Objects.hash(alias, getValue());
    }
  };
}
