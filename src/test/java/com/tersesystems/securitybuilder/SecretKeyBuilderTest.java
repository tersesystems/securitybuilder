package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.Provider;
import java.security.spec.KeySpec;
import java.util.Random;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.Test;

public class SecretKeyBuilderTest {

  @Test
  public void testAlgorithm() throws Exception {
    String password = "changeit";
    String salt = "abc123";
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
    SecretKey secretKey = SecretKeyBuilder.builder()
        .withAlgorithm("PBKDF2WithHmacSHA1")
        .withKeySpec(keySpec)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA1");
  }

  @Test
  public void testAlgorithmAndProvider() throws Exception {
    String password = "changeit";
    String salt = "abc123";
    Provider provider = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").getProvider();

    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
    SecretKey secretKey = SecretKeyBuilder.builder()
        .withAlgorithmAndProvider("PBKDF2WithHmacSHA1", provider.getName())
        .withKeySpec(keySpec)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA1");
  }

  @Test
  public void testSecretKeyS0ec() throws Exception {
    byte[] aesKeyData = getKeyData();

    SecretKey secretKey = SecretKeyBuilder.builder()
        .withSecretKeySpec("AES")
        .withData(aesKeyData)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }

  private byte[] getKeyData() {
    Random random = new Random();
    final byte[] bytes = new byte[256];
    random.nextBytes(bytes);
    return bytes;
  }
}
