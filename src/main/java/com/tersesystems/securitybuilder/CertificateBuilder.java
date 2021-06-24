package com.tersesystems.securitybuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Objects;
import org.slieb.throwables.SupplierWithThrowable;

/**
 * This class reads in certificates from input bytes, and will return <a
 * href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#CertificateFactory">X509Certificate</a>
 */
public class CertificateBuilder {

  private CertificateBuilder() {}

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {

    InputStage<X509Certificate> withX509();

    <T extends Certificate> InputStage<T> withAlgorithm(String algorithm);

    <T extends Certificate> InputStage<T> withAlgorithmAndProvider(
        String algorithm, String provider);
  }

  public interface InputStage<T extends Certificate> {

    BuildFinal<T> withByteBuffer(ByteBuffer byteBuffer);

    BuildFinal<T> withInputStream(InputStream inputStream);

    BuildFinal<T> withResource(String path, ClassLoader classLoader);

    BuildFinal<T> withPath(Path path);

    BuildFinal<T> withReader(Reader reader);

    BuildFinal<T> withString(String content);

    BuildFinal<T> withBytes(byte[] bytes);

    BuildFinal<T> withKeySpec(X509EncodedKeySpec keySpec);
  }

  // ---------------
  // Implementation
  // ---------------

  public interface BuildFinal<T extends Certificate> {

    T build() throws CertificateException;

    Collection<T> chain() throws CertificateException;

    CertPath certPath() throws CertificateException;

    CRL crl() throws CertificateException, CRLException;

    Collection<? extends CRL> crls() throws CertificateException, CRLException;
  }

  private static class InstanceStageImpl
      extends InstanceGenerator<CertificateFactory, CertificateException> implements InstanceStage {

    @Override
    public InputStage<X509Certificate> withX509() {
      return new InputStageImpl<>(getInstance().withAlgorithm("X.509"));
    }

    @Override
    public <T extends Certificate> InputStage<T> withAlgorithm(final String algorithm) {
      return new InputStageImpl<T>(getInstance().withAlgorithm(algorithm));
    }

    @Override
    public <T extends Certificate> InputStage<T> withAlgorithmAndProvider(
        final String algorithm, final String provider) {
      return new InputStageImpl<T>(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }
  }

  private static class InputStageImpl<T extends Certificate> implements InputStage<T> {

    private final SupplierWithThrowable<CertificateFactory, CertificateException> supplier;

    InputStageImpl(final SupplierWithThrowable<CertificateFactory, CertificateException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal<T> withString(final String content) {
      Objects.requireNonNull(content);
      return withBytes(content.getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public BuildFinal<T> withBytes(final byte[] bytes) {
      Objects.requireNonNull(bytes);
      return withInputStream(new ByteArrayInputStream(bytes));
    }

    @Override
    public BuildFinal<T> withKeySpec(final X509EncodedKeySpec keySpec) {
      return withBytes(keySpec.getEncoded());
    }

    @Override
    public BuildFinal<T> withByteBuffer(final ByteBuffer byteBuffer) {
      Objects.requireNonNull(byteBuffer);
      return withBytes(byteBuffer.array());
    }

    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<T> withResource(final String path, final ClassLoader classLoader) {
      Objects.requireNonNull(path);
      Objects.requireNonNull(classLoader);
      return new BuildFinalImpl<>(supplier, () -> classLoader.getResourceAsStream(path));
    }

    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<T> withPath(final Path path) {
      Objects.requireNonNull(path);
      return new BuildFinalImpl<>(supplier, () -> Files.newInputStream(path));
    }

    @Override
    public BuildFinal<T> withReader(final Reader reader) {
      Objects.requireNonNull(reader);

      SupplierWithThrowable<InputStream, IOException> inputStreamSupplier =
          () -> {
            final char[] charBuffer = new char[16 * 1024]; // 16K ought to be enough for anybody
            final StringBuilder builder = new StringBuilder();
            int numCharsRead;
            while ((numCharsRead = reader.read(charBuffer, 0, charBuffer.length)) != -1) {
              builder.append(charBuffer, 0, numCharsRead);
            }
            try (final InputStream targetStream =
                new ByteArrayInputStream(builder.toString().getBytes(StandardCharsets.UTF_8))) {
              return targetStream;
            } finally {
              reader.close();
            }
          };
      return new BuildFinalImpl<T>(supplier, inputStreamSupplier);
    }

    @Override
    public BuildFinal<T> withInputStream(final InputStream inputStream) {
      Objects.requireNonNull(inputStream);
      return new BuildFinalImpl<>(supplier, () -> inputStream);
    }
  }

  private static class BuildFinalImpl<T extends Certificate> implements BuildFinal<T> {

    private final SupplierWithThrowable<CertificateFactory, CertificateException> supplier;
    private final SupplierWithThrowable<InputStream, IOException> inputStreamSupplier;

    BuildFinalImpl(
        final SupplierWithThrowable<CertificateFactory, CertificateException> supplier,
        final SupplierWithThrowable<InputStream, IOException> inputStreamSupplier) {
      this.supplier = supplier;
      this.inputStreamSupplier = inputStreamSupplier;
    }

    @SuppressWarnings("unchecked")
    @Override
    public T build() throws CertificateException {
      return (T) supplier.getWithThrowable().generateCertificate(inputStreamSupplier.get());
    }

    @SuppressWarnings("unchecked")
    @Override
    public Collection<T> chain() throws CertificateException {
      return (Collection<T>)
          supplier.getWithThrowable().generateCertificates(inputStreamSupplier.get());
    }

    @Override
    public CertPath certPath() throws CertificateException {
      return supplier.getWithThrowable().generateCertPath(inputStreamSupplier.get());
    }

    @Override
    public CRL crl() throws CertificateException, CRLException {
      return supplier.getWithThrowable().generateCRL(inputStreamSupplier.get());
    }

    @Override
    public Collection<? extends CRL> crls() throws CertificateException, CRLException {
      return supplier.getWithThrowable().generateCRLs(inputStreamSupplier.get());
    }
  }
}
