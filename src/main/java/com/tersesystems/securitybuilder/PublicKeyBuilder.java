package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.SupplierWithThrowable;

public class PublicKeyBuilder {

  public interface InstanceStage {

    @NotNull
    <PK extends PublicKey> ParametersStage<PK> withAlgorithm(String algorithm);

    @NotNull
    <PK extends PublicKey> ParametersStage<PK> withAlgorithmAndProvider(
        String algorithm, String provider);

    @NotNull
    RSAParametersStage withRSA();

    @NotNull
    ECParametersStage withEC();

    @NotNull
    DSAParametersStage withDSA();
  }

  public interface ParametersStage<PK extends PublicKey> {

    @NotNull
    BuildFinal<PK> withKeySpec(KeySpec keySpec);
  }

  public interface EncodedParametersStage<PK extends PublicKey> {
    @NotNull
    BuildFinal<PK> withKeySpec(EncodedKeySpec keySpec);
  }

  public interface RSAParametersStage extends EncodedParametersStage<RSAPublicKey> {

    @NotNull
    BuildFinal<RSAPublicKey> withKeySpec(RSAPublicKeySpec keySpec);
  }

  public interface DSAParametersStage extends EncodedParametersStage<DSAPublicKey> {

    @NotNull
    BuildFinal<DSAPublicKey> withKeySpec(DSAPublicKeySpec keySpec);
  }

  public interface ECParametersStage extends EncodedParametersStage<ECPublicKey> {

    @NotNull
    BuildFinal<ECPublicKey> withKeySpec(ECPublicKeySpec keySpec);
  }

  static class RSAParametersStageImpl implements RSAParametersStage {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    RSAParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal<RSAPublicKey> withKeySpec(final RSAPublicKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (RSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }

    @NotNull
    @Override
    public BuildFinal<RSAPublicKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (RSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  public interface BuildFinal<PK extends PublicKey> {

    PK build() throws GeneralSecurityException;
  }

  static class InstanceStageImpl extends InstanceGenerator<KeyFactory, GeneralSecurityException>
      implements InstanceStage {

    @NotNull
    @Override
    public <PK extends PublicKey> ParametersStage<PK> withAlgorithm(final String algorithm) {
      return new ParametersStageImpl<>(getInstance().withAlgorithm(algorithm));
    }

    @NotNull
    @Override
    public <PK extends PublicKey> ParametersStage<PK> withAlgorithmAndProvider(
        final String algorithm, final String provider) {
      return new ParametersStageImpl<>(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }

    @NotNull
    @Override
    public RSAParametersStage withRSA() {
      return new RSAParametersStageImpl(getInstance().withAlgorithm("RSA"));
    }

    @NotNull
    @Override
    public ECParametersStage withEC() {
      return new ECParametersStageImpl(getInstance().withAlgorithm("EC"));
    }

    @NotNull
    @Override
    public DSAParametersStage withDSA() {
      return new DSAParametersStageImpl(getInstance().withAlgorithm("DSA"));
    }
  }

  static class ECParametersStageImpl implements ECParametersStage {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    ECParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal<ECPublicKey> withKeySpec(final ECPublicKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (ECPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }

    @NotNull
    @Override
    public BuildFinal<ECPublicKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (ECPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  static class DSAParametersStageImpl implements DSAParametersStage {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    DSAParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal<DSAPublicKey> withKeySpec(final DSAPublicKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }

    @NotNull
    @Override
    public BuildFinal<DSAPublicKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  static class ParametersStageImpl<PK extends PublicKey> implements ParametersStage<PK> {

    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    ParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @NotNull
    @Override
    public BuildFinal<PK> withKeySpec(final KeySpec keySpec) {
      return new BuildFinalImpl<>(() -> (PK) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  static class BuildFinalImpl<PK extends PublicKey> implements BuildFinal<PK> {

    private final SupplierWithThrowable<PK, GeneralSecurityException> supplier;

    BuildFinalImpl(final SupplierWithThrowable<PK, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public PK build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
