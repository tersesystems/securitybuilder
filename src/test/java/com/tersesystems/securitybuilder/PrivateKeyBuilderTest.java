package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import org.junit.jupiter.api.Test;

class PrivateKeyBuilderTest {

  @Test
  void builderWithRSA() throws GeneralSecurityException {
    final RSAPrivateKey exampleKey =
        (RSAPrivateKey)
            KeyPairBuilder.builder().withAlgorithm("RSA").withKeySize(2048).build().getPrivate();
    final RSAPrivateKeySpec rsaPrivateKeySpec =
        new RSAPrivateKeySpec(exampleKey.getModulus(), exampleKey.getPrivateExponent());
    final RSAPrivateKey privateKey =
        PrivateKeyBuilder.builder().withRSA().withKeySpec(rsaPrivateKeySpec).build();

    assertThat(privateKey).isNotNull();
  }

  @Test
  void builderWithEC() throws GeneralSecurityException {
    final ECPrivateKey exampleKey =
        (ECPrivateKey)
            KeyPairBuilder.builder().withAlgorithm("EC").withKeySize(128).build().getPrivate();
    final ECPrivateKeySpec privateKeySpec =
        new ECPrivateKeySpec(exampleKey.getS(), exampleKey.getParams());
    final ECPrivateKey privateKey =
        PrivateKeyBuilder.builder().withEC().withKeySpec(privateKeySpec).build();

    assertThat(privateKey).isNotNull();
  }

  @Test
  void builderWithDSA() throws GeneralSecurityException {
    final DSAPrivateKey exampleKey =
        (DSAPrivateKey)
            KeyPairBuilder.builder().withAlgorithm("DSA").withKeySize(1024).build().getPrivate();
    final DSAPrivateKeySpec privateKeySpec =
        new DSAPrivateKeySpec(
            exampleKey.getX(),
            exampleKey.getParams().getP(),
            exampleKey.getParams().getQ(),
            exampleKey.getParams().getG());
    final DSAPrivateKey privateKey =
        PrivateKeyBuilder.builder().withDSA().withKeySpec(privateKeySpec).build();

    assertThat(privateKey).isNotNull();
  }

  @Test
  void builderWithAlgorithm() throws GeneralSecurityException {
    final DSAPrivateKey exampleKey =
        (DSAPrivateKey)
            KeyPairBuilder.builder().withAlgorithm("DSA").withKeySize(1024).build().getPrivate();
    final DSAPrivateKeySpec privateKeySpec =
        new DSAPrivateKeySpec(
            exampleKey.getX(),
            exampleKey.getParams().getP(),
            exampleKey.getParams().getQ(),
            exampleKey.getParams().getG());
    final PrivateKey privateKey =
        PrivateKeyBuilder.builder().withAlgorithm("DSA").withKeySpec(privateKeySpec).build();

    assertThat(privateKey).isNotNull();
  }
}
