package com.tersesystems.securitybuilder;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import org.slieb.throwables.SupplierWithThrowable;

public class AlgorithmParametersBuilder {

  // https://docs.oracle.com/javase/8/docs/api/java/security/AlgorithmParameterGenerator.html

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }

  public interface InstanceStage {


    ParametersStage withAlgorithm(String algorithm);


    ParametersStage withAlgorithmAndProvider(String algorithm, String provider);
  }

  public interface ParametersStage {

    FinalStage withSpec(AlgorithmParameterSpec genParamSpec);


    FinalStage withSpec(AlgorithmParameterSpec genParamSpec, SecureRandom random);


    FinalStage withKeySize(int size);


    FinalStage withKeySize(int size, SecureRandom random);
  }

  public interface FinalStage {

    AlgorithmParameters build();
  }

  static class InstanceStageImpl
      extends InstanceGenerator<AlgorithmParameterGenerator, GeneralSecurityException>
      implements InstanceStage {


    @Override
    public ParametersStage withAlgorithm(final String algorithm) {
      return new ParametersStageImpl(getInstance().withAlgorithm(algorithm));
    }


    @Override
    public ParametersStage withAlgorithmAndProvider(
        final String algorithm, final String provider) {
      return new ParametersStageImpl(getInstance().withAlgorithmAndProvider(algorithm, provider));
    }
  }

  static class ParametersStageImpl implements ParametersStage {

    private final SupplierWithThrowable<AlgorithmParameterGenerator, GeneralSecurityException>
        supplier;

    ParametersStageImpl(
        final SupplierWithThrowable<AlgorithmParameterGenerator, GeneralSecurityException>
            supplier) {
      this.supplier = supplier;
    }


    @Override
    public FinalStage withSpec(final AlgorithmParameterSpec genParamSpec) {
      return new FinalStageImpl(
          () -> {
            final AlgorithmParameterGenerator parameterGenerator = supplier.getWithThrowable();
            parameterGenerator.init(genParamSpec);
            return parameterGenerator;
          });
    }


    @Override
    public FinalStage withSpec(
        final AlgorithmParameterSpec genParamSpec, final SecureRandom random) {
      return new FinalStageImpl(
          () -> {
            final AlgorithmParameterGenerator parameterGenerator = supplier.getWithThrowable();
            parameterGenerator.init(genParamSpec, random);
            return parameterGenerator;
          });
    }


    @Override
    public FinalStage withKeySize(final int size) {
      return new FinalStageImpl(
          () -> {
            final AlgorithmParameterGenerator parameterGenerator = supplier.getWithThrowable();
            parameterGenerator.init(size);
            return parameterGenerator;
          });
    }


    @Override
    public FinalStage withKeySize(final int size, final SecureRandom random) {
      return new FinalStageImpl(
          () -> {
            final AlgorithmParameterGenerator parameterGenerator = supplier.getWithThrowable();
            parameterGenerator.init(size, random);
            return parameterGenerator;
          });
    }
  }

  static class FinalStageImpl implements FinalStage {

    private final SupplierWithThrowable<AlgorithmParameterGenerator, GeneralSecurityException>
        supplier;

    FinalStageImpl(
        final SupplierWithThrowable<AlgorithmParameterGenerator, GeneralSecurityException>
            supplier) {
      this.supplier = supplier;
    }


    @Override
    public AlgorithmParameters build() {
      return supplier.get().generateParameters();
    }
  }
}
