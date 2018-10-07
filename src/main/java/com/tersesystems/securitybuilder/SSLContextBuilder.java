package com.tersesystems.securitybuilder;

import java.security.*;
import java.util.function.Supplier;
import javax.net.ssl.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slieb.throwables.SupplierWithThrowable;

public class SSLContextBuilder {
  private SSLContextBuilder() {}

  public interface InstanceStage {

    @NotNull
    BuildFinal withTLS();

    @NotNull
    BuildFinal withTLS12();

    @NotNull
    BuildFinal withProtocol(String algorithm);

    @NotNull
    BuildFinal withProtocol(String algorithm, String provider);
  }

  static class InstanceStageImpl extends InstanceGenerator<SSLContext, GeneralSecurityException>
      implements InstanceStage {

    @NotNull
    @Override
    public BuildFinal withTLS() {
      return new BuildFinalImpl(getInstance().withProtocol("TLS"));
    }

    @NotNull
    @Override
    public BuildFinal withTLS12() {
      return new BuildFinalImpl(getInstance().withProtocol("TLSv1.2"));
    }

    @NotNull
    @Override
    public BuildFinal withProtocol(final String protocol) {
      return new BuildFinalImpl(getInstance().withProtocol(protocol));
    }

    @NotNull
    @Override
    public BuildFinal withProtocol(final String protocol, final String provider) {
      return new BuildFinalImpl(getInstance().withProtocolAndProvider(protocol, provider));
    }
  }

  public interface BuildFinal {
    @NotNull
    BuildFinal withTrustManager(TrustManager trustManager);

    @NotNull
    BuildFinal withTrustManager(Supplier<TrustManager> trustManagerSupplier);

    @NotNull
    BuildFinal withKeyManager(KeyManager keyManager);

    @NotNull
    BuildFinal withKeyManager(Supplier<KeyManager> keyManagerSupplier);

    @NotNull
    BuildFinal withSecureRandom(SecureRandom secureRandom);

    @NotNull
    BuildFinal withSecureRandom(Supplier<SecureRandom> secureRandomSupplier);

    SSLContext build() throws GeneralSecurityException;
  }

  static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<SSLContext, GeneralSecurityException> supplier;
    @Nullable private Supplier<TrustManager> trustManagerSupplier = () -> null;
    @Nullable private Supplier<KeyManager> keyManagerSupplier = () -> null;
    @Nullable private Supplier<SecureRandom> secureRandomSupplier = () -> null;

    public BuildFinalImpl(
        final SupplierWithThrowable<SSLContext, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal withTrustManager(final TrustManager trustManager) {
      this.trustManagerSupplier = () -> trustManager;
      return this;
    }

    @NotNull
    @Override
    public BuildFinal withTrustManager(final Supplier<TrustManager> trustManagerSupplier) {
      this.trustManagerSupplier = trustManagerSupplier;
      return this;
    }

    @NotNull
    @Override
    public BuildFinal withKeyManager(final KeyManager keyManager) {
      this.keyManagerSupplier = () -> keyManager;
      return this;
    }

    @NotNull
    @Override
    public BuildFinal withKeyManager(final Supplier<KeyManager> keyManagerSupplier) {
      this.keyManagerSupplier = keyManagerSupplier;
      return this;
    }

    @NotNull
    @Override
    public BuildFinal withSecureRandom(final SecureRandom secureRandom) {
      this.secureRandomSupplier = () -> secureRandom;
      return this;
    }

    @NotNull
    @Override
    public BuildFinal withSecureRandom(final Supplier<SecureRandom> secureRandomSupplier) {
      this.secureRandomSupplier = secureRandomSupplier;
      return this;
    }

    public SSLContext build() throws GeneralSecurityException {
      final KeyManager km = keyManagerSupplier.get();
      final KeyManager[] kms = (km == null) ? null : new KeyManager[] {km};

      final TrustManager tm = trustManagerSupplier.get();
      final TrustManager[] tms = (tm == null) ? null : new TrustManager[] {tm};

      final SSLContext sslContext = this.supplier.getWithThrowable();
      sslContext.init(kms, tms, secureRandomSupplier.get());
      return sslContext;
    }
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
