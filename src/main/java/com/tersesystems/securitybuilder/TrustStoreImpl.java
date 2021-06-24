package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Objects;
import java.util.Optional;

/**
 * A keystore containing trusted certificate entries.
 */
public class TrustStoreImpl extends AbstractKeyStore<TrustedCertificateEntry>
    implements TrustStore {

  protected TrustStoreImpl(final Builder builder) {
    super(builder);
  }


  public TrustedCertificateEntry putCertificate(String key, Certificate certificate) {
    return put(key, new KeyStore.TrustedCertificateEntry(certificate));
  }


  @Override
  public Optional<String> getCertificateAlias(final Certificate certificate)
      throws RuntimeKeyStoreException {
    try {
      return Optional.ofNullable(getKeyStore().getCertificateAlias(certificate));
    } catch (final KeyStoreException e) {
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
    } catch (final KeyStoreException e) {
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


    @Override
    public KeyStore.TrustedCertificateEntry getValue() {
      try {
        return (KeyStore.TrustedCertificateEntry) getKeyStore().getEntry(alias, null);
      } catch (final Exception e) {
        throw new RuntimeKeyStoreException(e);
      }
    }


    @Override
    public KeyStore.TrustedCertificateEntry setValue(
        final KeyStore.TrustedCertificateEntry value) {
      try {
        getKeyStore().setEntry(alias, value, null);
        return value;
      } catch (final KeyStoreException e) {
        throw new RuntimeKeyStoreException(e);
      }
    }


    @Override
    public boolean equals(final Object o) {
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
  }

  @Override
  public String toString() {
    return String.format("TrustStoreImpl(size = %s)", size());
  }
}
