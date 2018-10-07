package com.tersesystems.securitybuilder;

import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.SupplierWithThrowable;

public class PrivateKeyBuilder {

  public interface InstanceStage {

    @NotNull
    <T extends PrivateKey> PrivateKeySpecStage<T> withAlgorithm(String algorithm);

    @NotNull
    <T extends PrivateKey> PrivateKeySpecStage<T> withAlgorithmAndProvider(
        String algorithm, String provider);

    @NotNull
    RSAPrivateKeySpecStage withRSA();

    @NotNull
    DSAPrivateKeySpecStage withDSA();

    @NotNull
    ECPrivateKeySpecStage withEC();
  }

  public interface PrivateKeySpecStage<T extends PrivateKey> {
    @NotNull
    BuildFinal<T> withKeySpec(KeySpec keySpec);
  }

  public interface RSAPrivateKeySpecStage extends EncodedPrivateKeySpecStage<RSAPrivateKey> {
    @NotNull
    BuildFinal<RSAPrivateKey> withKeySpec(RSAPrivateKeySpec keySpec);
  }

  public interface DSAPrivateKeySpecStage extends EncodedPrivateKeySpecStage<DSAPrivateKey> {
    @NotNull
    BuildFinal<DSAPrivateKey> withKeySpec(DSAPrivateKeySpec keySpec);
  }

  public interface ECPrivateKeySpecStage extends EncodedPrivateKeySpecStage<ECPrivateKey> {
    @NotNull
    BuildFinal<ECPrivateKey> withKeySpec(ECPrivateKeySpec keySpec);
  }

  public interface EncodedPrivateKeySpecStage<T extends PrivateKey> {
    @NotNull
    BuildFinal<T> withKeySpec(EncodedKeySpec keySpec);
  }

  public interface BuildFinal<T extends PrivateKey> {
    T build() throws GeneralSecurityException;
  }

  static class InstanceStageImpl extends InstanceGenerator<KeyFactory, GeneralSecurityException>
      implements InstanceStage {
    @NotNull
    @Override
    public <T extends PrivateKey> PrivateKeySpecStage<T> withAlgorithm(final String algorithm) {
      return new PrivateKeySpecStageImpl<>(getInstance().withAlgorithm(algorithm));
    }

    @NotNull
    @Override
    public <T extends PrivateKey> PrivateKeySpecStage<T> withAlgorithmAndProvider(
        final String algorithm, final String provider) {
      return new PrivateKeySpecStageImpl<>(
          getInstance().withAlgorithmAndProvider(algorithm, provider));
    }

    @NotNull
    @Override
    public RSAPrivateKeySpecStage withRSA() {
      return new RSAPrivateKeySpecStageImpl(getInstance().withAlgorithm("RSA"));
    }

    @NotNull
    @Override
    public ECPrivateKeySpecStage withEC() {
      return new ECPrivateKeySpecStageImpl(getInstance().withAlgorithm("EC"));
    }

    @NotNull
    @Override
    public DSAPrivateKeySpecStage withDSA() {
      return new DSAPrivateKeySpecStageImpl(getInstance().withAlgorithm("DSA"));
    }
  }

  static class PrivateKeySpecStageImpl<T extends PrivateKey> implements PrivateKeySpecStage<T> {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    PrivateKeySpecStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<T> withKeySpec(final KeySpec keySpec) {
      return new BuildFinalImpl(() -> supplier.getWithThrowable().generatePrivate(keySpec));
    }
  }

  static class DSAPrivateKeySpecStageImpl implements DSAPrivateKeySpecStage {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    DSAPrivateKeySpecStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<DSAPrivateKey> withKeySpec(final DSAPrivateKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DSAPrivateKey) supplier.getWithThrowable().generatePrivate(keySpec));
    }

    @NotNull
    @Override
    public BuildFinal<DSAPrivateKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DSAPrivateKey) supplier.getWithThrowable().generatePrivate(keySpec));
    }
  }

  static class RSAPrivateKeySpecStageImpl implements RSAPrivateKeySpecStage {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    RSAPrivateKeySpecStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @SuppressWarnings("unchecked")
    @Override
    public BuildFinal<RSAPrivateKey> withKeySpec(final RSAPrivateKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (RSAPrivateKey) supplier.getWithThrowable().generatePrivate(keySpec));
    }

    @NotNull
    @Override
    public BuildFinal<RSAPrivateKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (RSAPrivateKey) supplier.getWithThrowable().generatePrivate(keySpec));
    }
  }

  static class ECPrivateKeySpecStageImpl implements ECPrivateKeySpecStage {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    ECPrivateKeySpecStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal<ECPrivateKey> withKeySpec(final ECPrivateKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (ECPrivateKey) supplier.getWithThrowable().generatePrivate(keySpec));
    }

    @NotNull
    @Override
    public BuildFinal<ECPrivateKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (ECPrivateKey) supplier.getWithThrowable().generatePrivate(keySpec));
    }
  }

  static class BuildFinalImpl<T extends PrivateKey> implements BuildFinal<T> {

    private final SupplierWithThrowable<T, GeneralSecurityException> supplier;

    BuildFinalImpl(final SupplierWithThrowable<T, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public T build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
