package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class KeyPairBuilderTest {

  @Test
  void testWithAlgorithm() throws GeneralSecurityException {
    final KeyPair keyPair = KeyPairBuilder.builder().withAlgorithm("RSA").withKeySize(2048).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithRSA() throws GeneralSecurityException {
    final RSAKeyPair keyPair = KeyPairBuilder.builder().withRSA().withKeySize(2048).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithDSA() throws GeneralSecurityException {
    final DSAKeyPair keyPair = KeyPairBuilder.builder().withDSA().withKeySize(1024).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("DSA");
  }

  @Test
  void testWithEC() throws GeneralSecurityException {
    final ECKeyPair keyPair = KeyPairBuilder.builder().withEC().withKeySize(224).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("EC");
  }
}
