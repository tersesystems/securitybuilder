package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

public class SecretKeyGeneratorTest {

  @Test
  public void testSecretKeyGeneration() throws GeneralSecurityException {
    SecretKey aesSecretKey = SecretKeyGenerator.generate().withAES().withKeySize(256).build();
    assertThat(aesSecretKey.getAlgorithm()).isEqualTo("AES");
  }
}
