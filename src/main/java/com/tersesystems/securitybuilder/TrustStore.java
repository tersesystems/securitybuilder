package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

public interface TrustStore extends Map<String, KeyStore.TrustedCertificateEntry> {


  static TrustStore create(final KeyStore keyStore) {
    return new TrustStoreImpl(
        new Builder() {

          @Override
          public KeyStore getKeyStore() throws KeyStoreException {
            return keyStore;
          }


          @Override
          public ProtectionParameter getProtectionParameter(final String alias)
              throws KeyStoreException {
            return null;
          }
        });
  }

  static TrustStore create(
      final Map<? extends String, ? extends Certificate> certificates) {
    TrustStore trustStore = create();
    certificates.forEach(
        (alias, cert) -> {
          trustStore.put(alias, new TrustedCertificateEntry(cert));
        });
    return trustStore;
  }

  static <T extends Certificate> TrustStore create(
      final List<T> certificates, final Function<T, String> aliasFunction) {
    TrustStore trustStore = create();
    certificates.forEach(
        (cert) -> {
          String alias = aliasFunction.apply(cert);
          trustStore.put(alias, new TrustedCertificateEntry(cert));
        });
    return trustStore;
  }

  static TrustStore create(
      final CertStore certStore,
      final Function<Certificate, String> aliasFunction) {
    try {
      TrustStore trustStore = create();
      certStore
          .getCertificates(new X509CertSelector())
          .forEach(
              cert -> {
                String alias = aliasFunction.apply(cert);
                trustStore.put(alias, new TrustedCertificateEntry(cert));
              });
      return trustStore;
    } catch (CertStoreException e) {
      throw new IllegalStateException(e);
    }
  }

  static TrustStore create(final KeyStore.Builder builder) {
    return new TrustStoreImpl(builder);
  }

  static TrustStore create() {
    return create(KeyStoreBuilder.empty());
  }

  static TrustStore system() {
    try {
      return TrustStore.create(KeyStoreDefaults.getCacertsKeyStore());
    } catch (final Exception e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  KeyStore getKeyStore();

  TrustedCertificateEntry putCertificate(String key, Certificate certificate);

  Optional<String> getCertificateAlias(Certificate certificate)
      throws RuntimeKeyStoreException;
}
