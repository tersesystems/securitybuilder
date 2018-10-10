package com.tersesystems.securitybuilder;

import static java.util.Collections.singletonList;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.util.List;
import java.util.function.Supplier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import org.slieb.throwables.SupplierWithThrowable;

public class KeyManagerBuilder {

  private KeyManagerBuilder() {
  }

  public static KeyManagerFactoryStage builder() {
    return new KeyManagerFactoryStageImpl();
  }

  public interface KeyManagerFactoryStage {

    SunParametersStage withSunX509();


    SunParametersStage withSunX509(String provider);


    NewSunParametersStage withNewSunX509();


    NewSunParametersStage withNewSunX509(String provider);
  }

  public interface SunParametersStage {

    SunPasswordStage withKeyStore(KeyStore keyStore);


    BuilderFinal withPrivateKeyStore(PrivateKeyStore privateKeyStore);


    SunPasswordStage withKeyStore(
        SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier);


    SunPasswordStage withDefaultKeyStore();
  }

  public interface NewSunParametersStage {

    BuilderFinal withKeyStore(KeyStore keyStore, char[] password);


    BuilderFinal withPrivateKeyStore(PrivateKeyStore privateKeyStore);


    BuilderFinal withBuilders(List<KeyStore.Builder> builders);


    BuilderFinal withBuilders(Supplier<List<KeyStore.Builder>> builders);

    // Technically there should be a NewSunPasswordStage, but under what circumstance
    // are you going to do that?

    BuilderFinal withDefaultKeyStoreAndPassword();
  }

  public interface SunPasswordStage {


    BuilderFinal withPassword(PasswordProtection passwordProtection);


    BuilderFinal withPassword(char[] password);

    /**
     * Uses the password defined in the system property `javax.net.ssl.keyStorePassword`.
     */

    BuilderFinal withDefaultPassword();
  }

  public interface BuilderFinal {


    X509ExtendedKeyManager build() throws GeneralSecurityException;
  }

  static class KeyManagerFactoryStageImpl
      extends InstanceGenerator<KeyManagerFactory, GeneralSecurityException>
      implements KeyManagerFactoryStage {

    @Override
    public SunParametersStage withSunX509() {
      return new SunParametersStageImpl();
    }


    @Override
    public SunParametersStage withSunX509(final String provider) {
      return new SunParametersStageImpl(provider);
    }


    @Override
    public NewSunParametersStage withNewSunX509() {
      return new NewSunParametersStageImpl(getInstance().withAlgorithm("NewSunX509"));
    }


    @Override
    public NewSunParametersStage withNewSunX509(final String provider) {
      return new NewSunParametersStageImpl(
          getInstance().withAlgorithmAndProvider("NewSunX509", provider));
    }
  }

  static class SunPasswordStageImpl implements SunPasswordStage {

    private final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException>
        keyManagerFactory;
    private final Supplier<KeyStore> keyStore;

    SunPasswordStageImpl(
        final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException> keyManagerFactory,
        final Supplier<KeyStore> keyStore) {
      this.keyManagerFactory = keyManagerFactory;
      this.keyStore = keyStore;
    }

    @Override
    public BuilderFinal withPassword(
        final PasswordProtection passwordProtection) {
      return withPassword(passwordProtection.getPassword());
    }


    @Override
    public BuilderFinal withPassword(final char[] password) {
      return new BuilderFinalImpl(
          () -> {
            final KeyManagerFactory keyManagerFactory = this.keyManagerFactory.get();
            final KeyStore keyStore = this.keyStore.get();
            keyManagerFactory.init(keyStore, password);
            return keyManagerFactory;
          });
    }


    public BuilderFinal withDefaultPassword() {
      return new BuilderFinalImpl(
          () -> {
            final KeyManagerFactory keyManagerFactory = this.keyManagerFactory.get();
            final KeyStore keyStore = this.keyStore.get();
            keyManagerFactory.init(
                keyStore, System.getProperty("javax.net.ssl.keyStorePassword", "").toCharArray());
            return keyManagerFactory;
          });
    }
  }

  static class SunParametersStageImpl
      extends InstanceGenerator<KeyManagerFactory, GeneralSecurityException>
      implements SunParametersStage {

    private static final String sunX509 = "SunX509";
    private String provider = null;

    SunParametersStageImpl() {
    }

    SunParametersStageImpl(final String provider) {
      this.provider = provider;
    }

    @Override
    public SunPasswordStage withKeyStore(final KeyStore keyStore) {
      return withKeyStore(() -> keyStore);
    }

    @Override
    public BuilderFinal withPrivateKeyStore(
        final PrivateKeyStore privateKeyStore) {
      try {
        PasswordProtection passwordProtection =
            (PasswordProtection) privateKeyStore.getBuilder().getProtectionParameter("default");
        return withKeyStore(privateKeyStore::getKeyStore)
            .withPassword(passwordProtection.getPassword());
      } catch (KeyStoreException e) {
        throw new IllegalStateException(e);
      }
    }


    @Override
    public SunPasswordStage withKeyStore(
        final SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier) {
      return new SunPasswordStageImpl(
          (provider == null)
              ? getInstance().withAlgorithm(sunX509)
              : getInstance().withAlgorithmAndProvider(sunX509, provider),
          keyStoreSupplier);
    }


    @Override
    public SunPasswordStage withDefaultKeyStore() {
      return withKeyStore(() -> null);
    }
  }

  static class NewSunParametersStageImpl implements NewSunParametersStage {

    private final Supplier<KeyManagerFactory> supplier;

    NewSunParametersStageImpl(final Supplier<KeyManagerFactory> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuilderFinal withPrivateKeyStore(
        final PrivateKeyStore privateKeyStore) {
      return withBuilders(() -> singletonList(privateKeyStore.getBuilder()));
    }


    @Override
    public BuilderFinal withKeyStore(
        final KeyStore keyStore, final char[] keyStorePassword) {
      return withBuilders(
          () -> singletonList(KeyManagerKeyStoreBuilder.newInstance(keyStore, keyStorePassword)));
    }


    @Override
    public BuilderFinal withBuilders(final List<KeyStore.Builder> builders) {
      return withBuilders(() -> builders);
    }


    @Override
    public BuilderFinal withBuilders(final Supplier<List<KeyStore.Builder>> builders) {
      return new BuilderFinalImpl(
          () -> {
            final KeyManagerFactory kmf = supplier.get();
            kmf.init(new KeyStoreBuilderParameters(builders.get()));
            return kmf;
          });
    }


    @Override
    public BuilderFinal withDefaultKeyStoreAndPassword() {
      return new BuilderFinalImpl(
          () -> {
            final KeyManagerFactory kmf = supplier.get();
            kmf.init(null, null);
            return kmf;
          });
    }
  }

  static class BuilderFinalImpl implements BuilderFinal {

    private final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException>
        keyManagerFactory;

    BuilderFinalImpl(
        final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException>
            keyManagerFactory) {
      this.keyManagerFactory = keyManagerFactory;
    }


    @Override
    public X509ExtendedKeyManager build() throws GeneralSecurityException {
      return (X509ExtendedKeyManager) keyManagerFactory.getWithThrowable().getKeyManagers()[0];
    }
  }
}
