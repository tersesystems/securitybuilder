package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.Provider;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class SecretKeyBuilderTest {

  @Test
  public void testAlgorithm() throws Exception {
    byte[] aesKeyData = "abc123".getBytes();

    Provider provider = SecretKeyFactory.getInstance("AES").getProvider();

    KeySpec keySpec = new SecretKeySpec(aesKeyData, "AES");
    SecretKey secretKey = SecretKeyBuilder.builder()
        .withAlgorithmAndProvider("AES", provider.getName())
        .withKeySpec(keySpec)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }

  @Test
  public void testAlgorithmAndProvider() throws Exception {
    byte[] aesKeyData = "abc123".getBytes();

    Provider provider = SecretKeyFactory.getInstance("AES").getProvider();

    KeySpec keySpec = new SecretKeySpec(aesKeyData, "AES");
    SecretKey secretKey = SecretKeyBuilder.builder()
        .withAlgorithmAndProvider("AES", provider.getName())
        .withKeySpec(keySpec)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }

  @Test
  public void testSecretKeySpec() throws Exception {
    byte[] aesKeyData = "abc123".getBytes();

    SecretKey secretKey = SecretKeyBuilder.builder()
        .withSecretKeySpec("AES")
        .withData(aesKeyData)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }

}
