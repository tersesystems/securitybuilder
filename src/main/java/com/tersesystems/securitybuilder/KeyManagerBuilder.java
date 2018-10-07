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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slieb.throwables.SupplierWithThrowable;

public class KeyManagerBuilder {
  private KeyManagerBuilder() {}

  public interface KeyManagerFactoryStage {
    @NotNull
    SunParametersStage withSunX509();

    @NotNull
    SunParametersStage withSunX509(@NotNull String provider);

    @NotNull
    NewSunParametersStage withNewSunX509();

    @NotNull
    NewSunParametersStage withNewSunX509(@NotNull String provider);
  }

  public interface SunParametersStage {
    @NotNull
    SunPasswordStage withKeyStore(@NotNull KeyStore keyStore);

    @NotNull
    BuilderFinal withPrivateKeyStore(@NotNull PrivateKeyStore privateKeyStore);

    @NotNull
    SunPasswordStage withKeyStore(
        @NotNull SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier);

    @NotNull
    SunPasswordStage withDefaultKeyStore();
  }

  public interface NewSunParametersStage {
    @NotNull
    BuilderFinal withKeyStore(@NotNull KeyStore keyStore, @NotNull char[] password);

    @NotNull
    BuilderFinal withPrivateKeyStore(@NotNull PrivateKeyStore privateKeyStore);

    @NotNull
    BuilderFinal withBuilders(@NotNull List<KeyStore.Builder> builders);

    @NotNull
    BuilderFinal withBuilders(@NotNull Supplier<List<KeyStore.Builder>> builders);

    // Technically there should be a NewSunPasswordStage, but under what circumstance
    // are you going to do that?
    @NotNull
    BuilderFinal withDefaultKeyStoreAndPassword();
  }

  static class KeyManagerFactoryStageImpl
      extends InstanceGenerator<KeyManagerFactory, GeneralSecurityException>
      implements KeyManagerFactoryStage {
    @NotNull
    @Override
    public SunParametersStage withSunX509() {
      return new SunParametersStageImpl();
    }

    @NotNull
    @Override
    public SunParametersStage withSunX509(@NotNull final String provider) {
      return new SunParametersStageImpl(provider);
    }

    @NotNull
    @Override
    public NewSunParametersStage withNewSunX509() {
      return new NewSunParametersStageImpl(getInstance().withAlgorithm("NewSunX509"));
    }

    @NotNull
    @Override
    public NewSunParametersStage withNewSunX509(@NotNull final String provider) {
      return new NewSunParametersStageImpl(
          getInstance().withAlgorithmAndProvider("NewSunX509", provider));
    }
  }

  public interface SunPasswordStage {

    @NotNull
    BuilderFinal withPassword(PasswordProtection passwordProtection);

    @NotNull
    BuilderFinal withPassword(char[] password);

    /** Uses the password defined in the system property `javax.net.ssl.keyStorePassword`. */
    @NotNull
    BuilderFinal withDefaultPassword();
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
    public @NotNull BuilderFinal withPassword(
        @NotNull final PasswordProtection passwordProtection) {
      return withPassword(passwordProtection.getPassword());
    }

    @NotNull
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

    @NotNull
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
    @Nullable private String provider = null;

    SunParametersStageImpl() {}

    SunParametersStageImpl(@Nullable final String provider) {
      this.provider = provider;
    }

    @Override
    public @NotNull SunPasswordStage withKeyStore(@NotNull final KeyStore keyStore) {
      return withKeyStore(() -> keyStore);
    }

    @Override
    public @NotNull BuilderFinal withPrivateKeyStore(
        @NotNull final PrivateKeyStore privateKeyStore) {
      try {
        PasswordProtection passwordProtection =
            (PasswordProtection) privateKeyStore.getBuilder().getProtectionParameter("default");
        return withKeyStore(privateKeyStore::getKeyStore)
            .withPassword(passwordProtection.getPassword());
      } catch (KeyStoreException e) {
        throw new IllegalStateException(e);
      }
    }

    @NotNull
    @Override
    public SunPasswordStage withKeyStore(
        @NotNull final SupplierWithThrowable<KeyStore, Exception> keyStoreSupplier) {
      return new SunPasswordStageImpl(
          (provider == null)
              ? getInstance().withAlgorithm(sunX509)
              : getInstance().withAlgorithmAndProvider(sunX509, provider),
          keyStoreSupplier);
    }

    @NotNull
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
    public @NotNull BuilderFinal withPrivateKeyStore(
        @NotNull final PrivateKeyStore privateKeyStore) {
      return withBuilders(() -> singletonList(privateKeyStore.getBuilder()));
    }

    @NotNull
    @Override
    public BuilderFinal withKeyStore(
        @NotNull final KeyStore keyStore, @NotNull final char[] keyStorePassword) {
      return withBuilders(
          () -> singletonList(KeyManagerKeyStoreBuilder.newInstance(keyStore, keyStorePassword)));
    }

    @NotNull
    @Override
    public BuilderFinal withBuilders(@NotNull final List<KeyStore.Builder> builders) {
      return withBuilders(() -> builders);
    }

    @NotNull
    @Override
    public BuilderFinal withBuilders(@NotNull final Supplier<List<KeyStore.Builder>> builders) {
      return new BuilderFinalImpl(
          () -> {
            final KeyManagerFactory kmf = supplier.get();
            kmf.init(new KeyStoreBuilderParameters(builders.get()));
            return kmf;
          });
    }

    @NotNull
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

  public interface BuilderFinal {
    @NotNull
    X509ExtendedKeyManager build() throws GeneralSecurityException;
  }

  static class BuilderFinalImpl implements BuilderFinal {

    private final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException>
        keyManagerFactory;

    BuilderFinalImpl(
        final SupplierWithThrowable<KeyManagerFactory, GeneralSecurityException>
            keyManagerFactory) {
      this.keyManagerFactory = keyManagerFactory;
    }

    @NotNull
    @Override
    public X509ExtendedKeyManager build() throws GeneralSecurityException {
      return (X509ExtendedKeyManager) keyManagerFactory.getWithThrowable().getKeyManagers()[0];
    }
  }

  public static KeyManagerFactoryStage builder() {
    return new KeyManagerFactoryStageImpl();
  }
}
