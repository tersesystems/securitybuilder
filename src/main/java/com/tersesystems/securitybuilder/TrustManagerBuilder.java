package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.PKIXBuilderParameters;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Creates a <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#TrustManager">TrustManager</a>.
 */
public class TrustManagerBuilder {

  private TrustManagerBuilder() {
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {


    ParametersStage withAlgorithm(String algorithm);


    ParametersStage withAlgorithmAndProvider(String algorithm, String provider);


    ParametersStage withDefaultAlgorithm();
  }

  public interface ParametersStage {

    BuilderFinal withKeyStore(KeyStore keyStore);


    BuilderFinal withKeyStore(SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier);


    BuilderFinal withDefaultKeystore();


    BuilderFinal withPKIXBuilderParameters(PKIXBuilderParameters parameters);


    BuilderFinal withPKIXBuilderParameters(
        SupplierWithThrowable<PKIXBuilderParameters, Exception> params);


    BuilderFinal withTrustStore(TrustStore trustStore);
  }

  public interface BuilderFinal {


    X509ExtendedTrustManager build() throws Exception;
  }

  private static class InstanceStageImpl
      extends InstanceGenerator<TrustManagerFactory, GeneralSecurityException>
      implements InstanceStage {

    @Override
    public ParametersStage withAlgorithm(final String algorithm) {
      return new ParametersStageImpl(getInstance().withAlgorithm(algorithm));
    }


    @Override
    public ParametersStage withAlgorithmAndProvider(
        final String algorithm, final String provider) {
      return new ParametersStageImpl(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }


    @Override
    public ParametersStage withDefaultAlgorithm() {
      return new ParametersStageImpl(getInstance().withDefaultAlgorithm());
    }
  }

  private static class ParametersStageImpl implements ParametersStage {

    private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
        trustManagerFactory;

    ParametersStageImpl(
        final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
            trustManagerFactory) {
      this.trustManagerFactory = trustManagerFactory;
    }


    @Override
    public BuilderFinal withKeyStore(final KeyStore keyStore) {
      return new BuilderFinalKeyStoreImpl(trustManagerFactory, () -> keyStore);
    }


    @Override
    public BuilderFinal withKeyStore(
        final SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier) {
      return new BuilderFinalKeyStoreImpl(trustManagerFactory, keyStoreSupplier);
    }


    @Override
    public BuilderFinal withDefaultKeystore() {
      return new BuilderFinalKeyStoreImpl(
          trustManagerFactory, KeyStoreDefaults::getCacertsKeyStore);
    }

    @Override
    public BuilderFinal withTrustStore(final TrustStore trustStore) {
      return new BuilderFinalKeyStoreImpl(trustManagerFactory, trustStore::getKeyStore);
    }


    @Override
    public BuilderFinal withPKIXBuilderParameters(final PKIXBuilderParameters params) {
      return new BuilderFinalParametersImpl(trustManagerFactory, () -> params);
    }


    @Override
    public BuilderFinal withPKIXBuilderParameters(
        final SupplierWithThrowable<PKIXBuilderParameters, Exception> params) {
      return new BuilderFinalParametersImpl(trustManagerFactory, params);
    }
  }

  private static class BuilderFinalKeyStoreImpl implements BuilderFinal {

    private final SupplierWithThrowable<KeyStore, Exception> keyStore;

    private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
        trustManagerFactory;

    BuilderFinalKeyStoreImpl(
        final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> tmf,

        final SupplierWithThrowable<KeyStore, Exception> keyStore) {
      this.trustManagerFactory = tmf;
      this.keyStore = keyStore;
    }


    public X509ExtendedTrustManager build() throws Exception {
      final TrustManagerFactory tmf = trustManagerFactory.getWithThrowable();
      tmf.init(keyStore.getWithThrowable());
      return (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
    }
  }

  private static class BuilderFinalParametersImpl implements BuilderFinal {

    private final SupplierWithThrowable<PKIXBuilderParameters, Exception> parameters;

    private final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException>
        trustManagerFactory;

    BuilderFinalParametersImpl(
        final SupplierWithThrowable<TrustManagerFactory, GeneralSecurityException> tmf,
        final SupplierWithThrowable<PKIXBuilderParameters, Exception> parameters) {
      this.trustManagerFactory = tmf;
      this.parameters = parameters;
    }


    @Override
    public X509ExtendedTrustManager build() throws Exception {
      final TrustManagerFactory tmf = trustManagerFactory.getWithThrowable();
      tmf.init(new CertPathTrustManagerParameters(parameters.getWithThrowable()));
      return (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
    }
  }
}
