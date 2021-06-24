package com.tersesystems.securitybuilder;

import java.security.GeneralSecurityException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class KeyPairCreatorTest {

  @Test
  void testWithAlgorithm() throws GeneralSecurityException {
    final KeyPair keyPair =
        KeyPairCreator.creator().withAlgorithm("RSA").withKeySize(2048).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithRSA() throws GeneralSecurityException {
    final RSAKeyPair keyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithDSA() throws GeneralSecurityException {
    final DSAKeyPair keyPair = KeyPairCreator.creator().withDSA().withKeySize(1024).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("DSA");
  }

  @Test
  void testWithEC() throws GeneralSecurityException {
    final ECKeyPair keyPair = KeyPairCreator.creator().withEC().withKeySize(224).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("EC");
  }
}
