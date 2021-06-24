package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

public class SecretKeyBuilderTest {

  @Test
  public void testAES() throws Exception {
    byte[] aesKeyData = "abc123".getBytes();

    SecretKey secretKey = SecretKeyBuilder.builder().withAES().withData(aesKeyData).build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }

  @Test
  public void testSecretKeySpec() throws Exception {
    byte[] aesKeyData = "abc123".getBytes();

    SecretKey secretKey =
        SecretKeyBuilder.builder().withSecretKeySpec("AES").withData(aesKeyData).build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }
}
