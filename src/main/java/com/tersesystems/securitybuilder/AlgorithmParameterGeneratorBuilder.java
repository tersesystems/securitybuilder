package com.tersesystems.securitybuilder;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import org.jetbrains.annotations.NotNull;
import org.slieb.throwables.SupplierWithThrowable;

public class AlgorithmParameterGeneratorBuilder {

  // https://docs.oracle.com/javase/8/docs/api/java/security/AlgorithmParameterGenerator.html

  public interface InstanceStage {

    @NotNull
    ParametersStage withAlgorithm(@NotNull String algorithm);

    @NotNull
    ParametersStage withAlgorithmAndProvider(@NotNull String algorithm, @NotNull String provider);
  }

  public interface ParametersStage {
    @NotNull
    FinalStage withSpec(@NotNull AlgorithmParameterSpec genParamSpec);

    @NotNull
    FinalStage withSpec(@NotNull AlgorithmParameterSpec genParamSpec, @NotNull SecureRandom random);

    @NotNull
    FinalStage withKeySize(int size);

    @NotNull
    FinalStage withKeySize(int size, @NotNull SecureRandom random);
  }

  public interface FinalStage {
    AlgorithmParameters build();
  }

  static class InstanceStageImpl
      extends InstanceGenerator<AlgorithmParameterGenerator, GeneralSecurityException>
      implements InstanceStage {

    @NotNull
    @Override
    public ParametersStage withAlgorithm(@NotNull final String algorithm) {
      return new ParametersStageImpl(getInstance().withAlgorithm(algorithm));
    }

    @NotNull
    @Override
    public ParametersStage withAlgorithmAndProvider(
        @NotNull final String algorithm, @NotNull final String provider) {
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

    @NotNull
    @Override
    public FinalStage withSpec(@NotNull final AlgorithmParameterSpec genParamSpec) {
      return new FinalStageImpl(
          () -> {
            final AlgorithmParameterGenerator parameterGenerator = supplier.getWithThrowable();
            parameterGenerator.init(genParamSpec);
            return parameterGenerator;
          });
    }

    @NotNull
    @Override
    public FinalStage withSpec(
        @NotNull final AlgorithmParameterSpec genParamSpec, @NotNull final SecureRandom random) {
      return new FinalStageImpl(
          () -> {
            final AlgorithmParameterGenerator parameterGenerator = supplier.getWithThrowable();
            parameterGenerator.init(genParamSpec, random);
            return parameterGenerator;
          });
    }

    @NotNull
    @Override
    public FinalStage withKeySize(final int size) {
      return new FinalStageImpl(
          () -> {
            final AlgorithmParameterGenerator parameterGenerator = supplier.getWithThrowable();
            parameterGenerator.init(size);
            return parameterGenerator;
          });
    }

    @NotNull
    @Override
    public FinalStage withKeySize(final int size, @NotNull final SecureRandom random) {
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

  public static InstanceStage builder() {
    return new InstanceStageImpl();
  }
}
