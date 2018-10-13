package com.tersesystems.securitybuilder;

import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DomainLoadStoreParameter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Map;
import org.slieb.throwables.SupplierWithThrowable;

public class KeyStoreBuilder {

  private KeyStoreBuilder() {
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
    } catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static KeyStore empty(final String type, final String provider) {
    try {
      return new BuilderFinalImpl(
          () -> {
            KeyStore keyStore = KeyStore.getInstance(type, provider);
            keyStore.load(null);
            return keyStore;
          })
          .build();
    } catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public interface InstanceStage {


    ParametersStage withType(String type);


    ParametersStage withTypeAndProvider(String type, String provider);


    ParametersStage withDefaultType();


    DomainParametersStage withDomainType();
  }

  public interface DomainParametersStage {

    BuilderFinal withURIAndPasswordMap(
        URI uri, Map<String, KeyStore.ProtectionParameter> passwordMap);
  }

  public interface ParametersStage {

    PasswordStage withInputStream(InputStream inputStream);


    PasswordStage withPath(Path path);


    PasswordStage withFile(File file);
  }

  public interface PasswordStage {

    BuilderFinal withPassword(char[] password);


    BuilderFinal withNoPassword();
  }

  public interface BuilderFinal {


    KeyStore build() throws Exception;
  }

  private static class InstanceStageImpl extends InstanceGenerator<KeyStore, GeneralSecurityException>
      implements InstanceStage {


    @Override
    public ParametersStage withDefaultType() {
      return new ParametersStageImpl(getInstance().withDefaultType());
    }


    @Override
    public ParametersStage withType(final String type) {
      return new ParametersStageImpl(getInstance().withType(type));
    }


    @Override
    public DomainParametersStage withDomainType() {
      return new DomainParametersStageImpl(getInstance().withType("DKS"));
    }


    @Override
    public ParametersStage withTypeAndProvider(final String type, final String provider) {
      return new ParametersStageImpl(getInstance().withTypeAndProvider(type, provider));
    }
  }

  private static class ParametersStageImpl implements ParametersStage {

    private final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier;

    ParametersStageImpl(final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }


    @Override
    public PasswordStage withInputStream(final InputStream inputStream) {
      return new PasswordStageImpl(supplier, () -> inputStream);
    }


    @Override
    public PasswordStage withPath(final Path path) {
      return new PasswordStageImpl(supplier, () -> Files.newInputStream(path));
    }


    @Override
    public PasswordStage withFile(final File file) {
      return withPath(file.toPath());
    }
  }

  private static class DomainParametersStageImpl implements DomainParametersStage {

    private final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier;

    DomainParametersStageImpl(
        final SupplierWithThrowable<KeyStore, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }


    @Override
    public BuilderFinal withURIAndPasswordMap(
        final URI uri,
        final Map<String, KeyStore.ProtectionParameter> passwordMap) {
      return new BuilderFinalImpl(
          () -> {
            final KeyStore keyStore = supplier.getWithThrowable();
            keyStore.load(new DomainLoadStoreParameter(uri, passwordMap));
            return keyStore;
          });
    }
  }

  private static class PasswordStageImpl implements PasswordStage {

    private final SupplierWithThrowable<KeyStore, GeneralSecurityException> keyStore;
    private final SupplierWithThrowable<InputStream, Exception> inputStream;

    PasswordStageImpl(
        final SupplierWithThrowable<KeyStore, GeneralSecurityException> keyStore,
        final SupplierWithThrowable<InputStream, Exception> inputStream) {
      this.keyStore = keyStore;
      this.inputStream = inputStream;
    }


    @Override
    public BuilderFinal withPassword(final char[] password) {
      return new BuilderFinalImpl(
          () -> {
            final KeyStore keyStore = this.keyStore.getWithThrowable();
            keyStore.load(inputStream.getWithThrowable(), password);
            return keyStore;
          });
    }


    @Override
    public BuilderFinal withNoPassword() {
      return withPassword(null);
    }
  }

  private static class BuilderFinalImpl implements BuilderFinal {

    private final SupplierWithThrowable<KeyStore, Exception> supplier;

    BuilderFinalImpl(final SupplierWithThrowable<KeyStore, Exception> supplier) {
      this.supplier = supplier;
    }

    @Override
    public KeyStore build() throws Exception {
      return supplier.getWithThrowable();
    }
  }
}
