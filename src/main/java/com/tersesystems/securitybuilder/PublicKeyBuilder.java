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
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import org.slieb.throwables.SupplierWithThrowable;

public class PublicKeyBuilder {

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {


    <PK extends PublicKey> ParametersStage<PK> withAlgorithm(String algorithm);


    <PK extends PublicKey> ParametersStage<PK> withAlgorithmAndProvider(
        String algorithm, String provider);


    RSAParametersStage withRSA();

    ECParametersStage withEC();

    DSAParametersStage withDSA();

    DHParameterStage withDH();
  }

  public interface ParametersStage<PK extends PublicKey> {
    BuildFinal<PK> withKeySpec(KeySpec keySpec);
  }

  public interface EncodedParametersStage<PK extends PublicKey> {
    BuildFinal<PK> withKeySpec(EncodedKeySpec keySpec);
  }

  public interface RSAParametersStage extends EncodedParametersStage<RSAPublicKey> {
    BuildFinal<RSAPublicKey> withKeySpec(RSAPublicKeySpec keySpec);
  }

  public interface DSAParametersStage extends EncodedParametersStage<DSAPublicKey> {
    BuildFinal<DSAPublicKey> withKeySpec(DSAPublicKeySpec keySpec);
  }

  public interface ECParametersStage extends EncodedParametersStage<ECPublicKey> {
    BuildFinal<ECPublicKey> withKeySpec(ECPublicKeySpec keySpec);
  }

  public interface DHParameterStage extends EncodedParametersStage<DHPublicKey> {
    BuildFinal<DHPublicKey> withKeySpec(DHPublicKeySpec keySpec);
  }

  public interface BuildFinal<PK extends PublicKey> {
    PK build() throws GeneralSecurityException;
  }

  private static class InstanceStageImpl extends InstanceGenerator<KeyFactory, GeneralSecurityException>
      implements InstanceStage {


    @Override
    public <PK extends PublicKey> ParametersStage<PK> withAlgorithm(final String algorithm) {
      return new ParametersStageImpl<>(getInstance().withAlgorithm(algorithm));
    }


    @Override
    public <PK extends PublicKey> ParametersStage<PK> withAlgorithmAndProvider(
        final String algorithm, final String provider) {
      return new ParametersStageImpl<>(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }


    @Override
    public RSAParametersStage withRSA() {
      return new RSAParametersStageImpl(getInstance().withAlgorithm("RSA"));
    }


    @Override
    public ECParametersStage withEC() {
      return new ECParametersStageImpl(getInstance().withAlgorithm("EC"));
    }


    @Override
    public DSAParametersStage withDSA() {
      return new DSAParametersStageImpl(getInstance().withAlgorithm("DSA"));
    }

    @Override
    public DHParameterStage withDH() {
      return new DHParametersStageImpl(getInstance().withAlgorithm("DH"));
    }
  }

  private static class RSAParametersStageImpl implements RSAParametersStage {
    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    RSAParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal<RSAPublicKey> withKeySpec(final RSAPublicKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (RSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }

    @Override
    public BuildFinal<RSAPublicKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (RSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  private static class ECParametersStageImpl implements ECParametersStage {
    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    ECParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal<ECPublicKey> withKeySpec(final ECPublicKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (ECPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }

    @Override
    public BuildFinal<ECPublicKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (ECPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  private static class DSAParametersStageImpl implements DSAParametersStage {
    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    DSAParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal<DSAPublicKey> withKeySpec(final DSAPublicKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }

    @Override
    public BuildFinal<DSAPublicKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DSAPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  private static class ParametersStageImpl<PK extends PublicKey> implements ParametersStage<PK> {
    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    ParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    @SuppressWarnings("unchecked")
    public BuildFinal<PK> withKeySpec(final KeySpec keySpec) {
      return new BuildFinalImpl<>(() -> (PK) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  private static class DHParametersStageImpl<PK extends PublicKey> implements DHParameterStage {
    private final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier;

    DHParametersStageImpl(
        final SupplierWithThrowable<KeyFactory, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal<DHPublicKey> withKeySpec(final EncodedKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DHPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }

    @Override
    public BuildFinal<DHPublicKey> withKeySpec(final DHPublicKeySpec keySpec) {
      return new BuildFinalImpl<>(
          () -> (DHPublicKey) supplier.getWithThrowable().generatePublic(keySpec));
    }
  }

  private static class BuildFinalImpl<PK extends PublicKey> implements BuildFinal<PK> {

    private final SupplierWithThrowable<PK, GeneralSecurityException> supplier;

    BuildFinalImpl(final SupplierWithThrowable<PK, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }


    @Override
    public PK build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }
}
