package com.tersesystems.securitybuilder;

import java.security.*;
import java.security.cert.PKIXBuilderParameters;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.SupplierWithThrowable;

public class TrustManagerBuilder {

  private TrustManagerBuilder() {}

  public interface InstanceStage {

    @NotNull
    ParametersStage withAlgorithm(@NotNull String algorithm);

    @NotNull
    ParametersStage withAlgorithmAndProvider(@NotNull String algorithm, @NotNull String provider);

    @NotNull
    ParametersStage withDefaultAlgorithm();
  }

  public interface ParametersStage {
    @NotNull
    BuilderFinal withKeyStore(@NotNull KeyStore keyStore);

    @NotNull
    BuilderFinal withKeyStore(SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier);

    @NotNull
    BuilderFinal withDefaultKeystore();

    @NotNull
    BuilderFinal withPKIXBuilderParameters(@NotNull PKIXBuilderParameters parameters);

    @NotNull
    BuilderFinal withPKIXBuilderParameters(
        SupplierWithThrowable<PKIXBuilderParameters, Exception> params);

    @NotNull
    BuilderFinal withTrustStore(@NotNull TrustStore trustStore);
  }

  public interface BuilderFinal {
    @NotNull
    X509ExtendedTrustManager build() throws Exception;
  }

  static class InstanceStageImpl
      extends InstanceGenerator<TrustManagerFactory, GeneralSecurityException>
      implements InstanceStage {
    @NotNull
    @Override
    public ParametersStage withAlgorithm(@NotNull final String algorithm) {
      return new ParametersStageImpl(getInstance().withAlgorithm(algorithm));
    }

    @NotNull
    @Override
    public ParametersStage withAlgorithmAndProvider(
        @NotNull final String algorithm, @NotNull final String provider) {
      return new ParametersStageImpl(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }

    @NotNull
    @Override
    public ParametersStage withDefaultAlgorithm() {
      return new ParametersStageImpl(getInstance().withDefaultAlgorithm());
    }
  }

  static class ParametersStageImpl implements ParametersStage {

    private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
        trustManagerFactory;

    ParametersStageImpl(
        final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
            trustManagerFactory) {
      this.trustManagerFactory = trustManagerFactory;
    }

    @NotNull
    @Override
    public BuilderFinal withKeyStore(@NotNull final KeyStore keyStore) {
      return new BuilderFinalKeyStoreImpl(trustManagerFactory, () -> keyStore);
    }

    @NotNull
    @Override
    public BuilderFinal withKeyStore(
        final SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier) {
      return new BuilderFinalKeyStoreImpl(trustManagerFactory, keyStoreSupplier);
    }

    @NotNull
    @Override
    public BuilderFinal withDefaultKeystore() {
      return new BuilderFinalKeyStoreImpl(
          trustManagerFactory, KeyStoreDefaults::getCacertsKeyStore);
    }

    @Override
    public @NotNull BuilderFinal withTrustStore(@NotNull final TrustStore trustStore) {
      return new BuilderFinalKeyStoreImpl(trustManagerFactory, trustStore::getKeyStore);
    }

    @NotNull
    @Override
    public BuilderFinal withPKIXBuilderParameters(@NotNull final PKIXBuilderParameters params) {
      return new BuilderFinalParametersImpl(trustManagerFactory, () -> params);
    }

    @NotNull
    @Override
    public BuilderFinal withPKIXBuilderParameters(
        final SupplierWithThrowable<PKIXBuilderParameters, Exception> params) {
      return new BuilderFinalParametersImpl(trustManagerFactory, params);
    }
  }

  static class BuilderFinalKeyStoreImpl implements BuilderFinal {
    private final SupplierWithThrowable<KeyStore, Exception> keyStore;
    private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
        trustManagerFactory;

    BuilderFinalKeyStoreImpl(
        final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> tmf,
        final SupplierWithThrowable<KeyStore, Exception> keyStore) {
      this.trustManagerFactory = tmf;
      this.keyStore = keyStore;
    }

    @NotNull
    public X509ExtendedTrustManager build() throws Exception {
      final TrustManagerFactory tmf = trustManagerFactory.getWithThrowable();
      tmf.init(keyStore.getWithThrowable());
      return (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
    }
  }

  static class BuilderFinalParametersImpl implements BuilderFinal {
    private final SupplierWithThrowable<PKIXBuilderParameters, Exception> parameters;
    private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
        trustManagerFactory;

    BuilderFinalParametersImpl(
        final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> tmf,
        final SupplierWithThrowable<PKIXBuilderParameters, Exception> parameters) {
      this.trustManagerFactory = tmf;
      this.parameters = parameters;
    }

    @NotNull
    @Override
    public X509ExtendedTrustManager build() throws Exception {
      final TrustManagerFactory tmf = trustManagerFactory.getWithThrowable();
      tmf.init(new CertPathTrustManagerParameters(parameters.getWithThrowable()));
      return (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
    }
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
