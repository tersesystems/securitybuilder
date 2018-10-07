package com.tersesystems.securitybuilder;

import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Map;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.SupplierWithThrowable;

public class KeyStoreBuilder {

  private KeyStoreBuilder() {}

  public interface InstanceStage {

    @NotNull
    ParametersStage withType(@NotNull String type);

    @NotNull
    ParametersStage withTypeAndProvider(@NotNull String type, String provider);

    @NotNull
    ParametersStage withDefaultType();

    @NotNull
    DomainParametersStage withDomainType();
  }

  public interface DomainParametersStage {
    @NotNull
    BuilderFinal withURIAndPasswordMap(
        @NotNull URI uri, @NotNull Map<String, KeyStore.ProtectionParameter> passwordMap);
  }

  public interface ParametersStage {
    @NotNull
    PasswordStage withInputStream(@NotNull InputStream inputStream);

    @NotNull
    PasswordStage withPath(@NotNull Path path);

    @NotNull
    PasswordStage withFile(@NotNull File file);
  }

  public interface PasswordStage {
    @NotNull
    BuilderFinal withPassword(char[] password);

    @NotNull
    BuilderFinal withNoPassword();
  }

  public interface BuilderFinal {
    KeyStore build() throws Exception;
  }

  static class InstanceStageImpl extends InstanceGenerator<KeyStore, GeneralSecurityException>
      implements InstanceStage {

    @NotNull
    @Override
    public ParametersStage withDefaultType() {
      return new ParametersStageImpl(getInstance().withDefaultType());
    }

    @NotNull
    @Override
    public ParametersStage withType(@NotNull final String type) {
      return new ParametersStageImpl(getInstance().withType(type));
    }

    @NotNull
    @Override
    public DomainParametersStage withDomainType() {
      return new DomainParametersStageImpl(getInstance().withType("DKS"));
    }

    @NotNull
    @Override
    public ParametersStage withTypeAndProvider(@NotNull final String type, final String provider) {
      return new ParametersStageImpl(getInstance().withTypeAndProvider(type, provider));
    }
  }

  static class ParametersStageImpl implements ParametersStage {
    private final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier;

    ParametersStageImpl(final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public PasswordStage withInputStream(@NotNull final InputStream inputStream) {
      return new PasswordStageImpl(supplier, () -> inputStream);
    }

    @NotNull
    @Override
    public PasswordStage withPath(@NotNull final Path path) {
      return new PasswordStageImpl(supplier, () -> Files.newInputStream(path));
    }

    @NotNull
    @Override
    public PasswordStage withFile(@NotNull final File file) {
      return withPath(file.toPath());
    }
  }

  static class DomainParametersStageImpl implements DomainParametersStage {
    private final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier;

    DomainParametersStageImpl(
        final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuilderFinal withURIAndPasswordMap(
        @NotNull final URI uri,
        @NotNull final Map<String, KeyStore.ProtectionParameter> passwordMap) {
      return new BuilderFinalImpl(
          () -> {
            final KeyStore keyStore = supplier.getWithThrowable();
            keyStore.load(new DomainLoadStoreParameter(uri, passwordMap));
            return keyStore;
          });
    }
  }

  static class PasswordStageImpl implements PasswordStage {
    private final SupplierWithThrowable<KeyStore, GeneralSecurityException> keyStore;
    private final SupplierWithThrowable<InputStream, Exception> inputStream;

    PasswordStageImpl(
        final SupplierWithThrowable<KeyStore, GeneralSecurityException> keyStore,
        final SupplierWithThrowable<InputStream, Exception> inputStream) {
      this.keyStore = keyStore;
      this.inputStream = inputStream;
    }

    @NotNull
    @Override
    public BuilderFinal withPassword(final char[] password) {
      return new BuilderFinalImpl(
          () -> {
            final KeyStore keyStore = this.keyStore.getWithThrowable();
            keyStore.load(inputStream.getWithThrowable(), password);
            return keyStore;
          });
    }

    @NotNull
    @Override
    public BuilderFinal withNoPassword() {
      return withPassword(null);
    }
  }

  static class BuilderFinalImpl implements BuilderFinal {
    private final SupplierWithThrowable<KeyStore, Exception> supplier;

    BuilderFinalImpl(final SupplierWithThrowable<KeyStore, Exception> supplier) {
      this.supplier = supplier;
    }

    @Override
    public KeyStore build() throws Exception {
      return supplier.getWithThrowable();
    }
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public static KeyStore empty() {
    return empty(KeyStore.getDefaultType());
  }

  public static KeyStore empty(final String type) {
    try {
      return new BuilderFinalImpl(
              () -> {
                KeyStore keyStore = KeyStore.getInstance(type);
                keyStore.load(null);
                return keyStore;
              })
          .build();
    } catch (@NotNull final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static KeyStore empty(final String type, @NotNull final String provider) {
    try {
      return new BuilderFinalImpl(
              () -> {
                KeyStore keyStore = KeyStore.getInstance(type, provider);
                keyStore.load(null);
                return keyStore;
              })
          .build();
    } catch (@NotNull final Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
