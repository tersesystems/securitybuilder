package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.AlgorithmParameters;
import org.junit.jupiter.api.Test;

class AlgorithmParameterGeneratorBuilderTest {

  @Test
  public void testAlgorithmParameters() {
    final AlgorithmParameters algorithmParameters =
        AlgorithmParameterGeneratorBuilder.builder().withAlgorithm("DSA").withKeySize(1024).build();
    assertThat(algorithmParameters.getAlgorithm()).isEqualTo("DSA");
  }
}
