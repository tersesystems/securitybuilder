package com.tersesystems.securitybuilder;

import java.io.*;
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
import java.util.Collection;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slieb.throwables.SupplierWithThrowable;

/** This class uses CertificateFactory to generate a certificate. */
public class CertificateBuilder {
  private CertificateBuilder() {}

  public interface InstanceStage {
    @NotNull
    InputStage<X509Certificate> withX509();

    @NotNull
    <T extends Certificate> InputStage<T> withAlgorithm(@NotNull String algorithm);

    @NotNull
    <T extends Certificate> InputStage<T> withAlgorithmAndProvider(
        @NotNull String algorithm, @NotNull String provider);
  }

  public interface InputStage<T extends Certificate> {
    @NotNull
    BuildFinal<T> withByteBuffer(@NotNull ByteBuffer byteBuffer);

    @NotNull
    BuildFinal<T> withInputStream(@NotNull InputStream inputStream);

    @Nullable
    BuildFinal<T> withResource(@NotNull String path, @NotNull ClassLoader classLoader);

    @NotNull
    BuildFinal<T> withPath(@NotNull Path path);

    @NotNull
    BuildFinal<T> withReader(@NotNull Reader reader);

    @NotNull
    BuildFinal<T> withString(@NotNull String content);

    @NotNull
    BuildFinal<T> withBytes(@NotNull byte[] bytes);
  }

  public interface BuildFinal<T extends Certificate> {
    T build() throws CertificateException;

    Collection<T> chain() throws CertificateException;

    @SuppressWarnings("unchecked")
    CertPath certPath() throws CertificateException;

    CRL crl() throws CertificateException, CRLException;

    Collection<? extends CRL> crls() throws CertificateException, CRLException;
  }

  // ---------------
  // Implementation
  // ---------------

  static class InstanceStageImpl extends InstanceGenerator<CertificateFactory, CertificateException>
      implements InstanceStage {

    @NotNull
    @Override
    public InputStage<X509Certificate> withX509() {
      return new InputStageImpl<>(getInstance().withAlgorithm("X.509"));
    }

    @NotNull
    @Override
    public <T extends Certificate> InputStage<T> withAlgorithm(@NotNull final String algorithm) {
      return new InputStageImpl<T>(getInstance().withAlgorithm(algorithm));
    }

    @NotNull
    @Override
    public <T extends Certificate> InputStage<T> withAlgorithmAndProvider(
        @NotNull final String algorithm, @NotNull final String provider) {
      return new InputStageImpl<T>(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }
  }

  static class InputStageImpl<T extends Certificate> implements InputStage<T> {

    private final SupplierWithThrowable<CertificateFactory, CertificateException> supplier;

    InputStageImpl(final SupplierWithThrowable<CertificateFactory, CertificateException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal<T> withString(@NotNull final String content) {
      Objects.requireNonNull(content);
      return withBytes(content.getBytes(StandardCharsets.US_ASCII));
    }

    @NotNull
    @Override
    public BuildFinal<T> withBytes(@NotNull final byte[] bytes) {
      Objects.requireNonNull(bytes);

      return withInputStream(new ByteArrayInputStream(bytes));
    }

    @NotNull
    @Override
    public BuildFinal<T> withByteBuffer(@NotNull final ByteBuffer byteBuffer) {
      Objects.requireNonNull(byteBuffer);

      return withBytes(byteBuffer.array());
    }

    @Nullable
    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<T> withResource(
        @NotNull final String path, @NotNull final ClassLoader classLoader) {
      Objects.requireNonNull(path);
      Objects.requireNonNull(classLoader);
      return new BuildFinalImpl<T>(supplier, () -> classLoader.getResourceAsStream(path));
    }

    @NotNull
    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<T> withPath(@NotNull final Path path) {
      Objects.requireNonNull(path);
      return new BuildFinalImpl<T>(supplier, () -> Files.newInputStream(path));
    }

    @NotNull
    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<T> withReader(@NotNull final Reader reader) {
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

    @NotNull
    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<T> withInputStream(@NotNull final InputStream inputStream) {
      Objects.requireNonNull(inputStream);
      return new BuildFinalImpl<>(supplier, () -> inputStream);
    }
  }

  static class BuildFinalImpl<T extends Certificate> implements BuildFinal<T> {
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

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
