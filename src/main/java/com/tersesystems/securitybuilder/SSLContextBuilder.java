package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.function.Supplier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * Creates an <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SSLContext">SSLContext</a>.
 *
 * This API takes suppliers so you can do fun things with KeyManagerBuilder and TrustManagerBuilder inline.
 */
public class SSLContextBuilder {

  private SSLContextBuilder() {
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {

    BuildFinal withTLS();

    BuildFinal withTLS12();

    BuildFinal withProtocol(String algorithm);

    BuildFinal withProtocolAndProvider(String algorithm, String provider);
  }

  public interface BuildFinal {

    BuildFinal withTrustManager(TrustManager trustManager);

    BuildFinal withTrustManager(Supplier<TrustManager> trustManagerSupplier);

    BuildFinal withKeyManager(KeyManager keyManager);

    BuildFinal withKeyManager(Supplier<KeyManager> keyManagerSupplier);

    BuildFinal withSecureRandom(SecureRandom secureRandom);

    BuildFinal withSecureRandom(Supplier<SecureRandom> secureRandomSupplier);

    SSLContext build() throws GeneralSecurityException;
  }

  private static class InstanceStageImpl extends InstanceGenerator<SSLContext, GeneralSecurityException>
      implements InstanceStage {


    @Override
    public BuildFinal withTLS() {
      return new BuildFinalImpl(getInstance().withProtocol("TLS"));
    }


    @Override
    public BuildFinal withTLS12() {
      return new BuildFinalImpl(getInstance().withProtocol("TLSv1.2"));
    }


    @Override
    public BuildFinal withProtocol(final String protocol) {
      return new BuildFinalImpl(getInstance().withProtocol(protocol));
    }


    @Override
    public BuildFinal withProtocolAndProvider(final String protocol, final String provider) {
      return new BuildFinalImpl(getInstance().withProtocolAndProvider(protocol, provider));
    }
  }

  private static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<SSLContext, GeneralSecurityException> supplier;
    private Supplier<TrustManager> trustManagerSupplier = () -> null;
    private Supplier<KeyManager> keyManagerSupplier = () -> null;
    private Supplier<SecureRandom> secureRandomSupplier = () -> null;

    BuildFinalImpl(
        final SupplierWithThrowable<SSLContext, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }


    @Override
    public BuildFinal withTrustManager(final TrustManager trustManager) {
      this.trustManagerSupplier = () -> trustManager;
      return this;
    }


    @Override
    public BuildFinal withTrustManager(final Supplier<TrustManager> trustManagerSupplier) {
      this.trustManagerSupplier = trustManagerSupplier;
      return this;
    }


    @Override
    public BuildFinal withKeyManager(final KeyManager keyManager) {
      this.keyManagerSupplier = () -> keyManager;
      return this;
    }


    @Override
    public BuildFinal withKeyManager(final Supplier<KeyManager> keyManagerSupplier) {
      this.keyManagerSupplier = keyManagerSupplier;
      return this;
    }


    @Override
    public BuildFinal withSecureRandom(final SecureRandom secureRandom) {
      this.secureRandomSupplier = () -> secureRandom;
      return this;
    }


    @Override
    public BuildFinal withSecureRandom(final Supplier<SecureRandom> secureRandomSupplier) {
      this.secureRandomSupplier = secureRandomSupplier;
      return this;
    }


    public SSLContext build() throws GeneralSecurityException {
      final KeyManager km = keyManagerSupplier.get();
      final KeyManager[] kms = (km == null) ? null : new KeyManager[]{km};

      final TrustManager tm = trustManagerSupplier.get();
      final TrustManager[] tms = (tm == null) ? null : new TrustManager[]{tm};

      final SSLContext sslContext = this.supplier.getWithThrowable();
      sslContext.init(kms, tms, secureRandomSupplier.get());
      return sslContext;
    }
  }
}
