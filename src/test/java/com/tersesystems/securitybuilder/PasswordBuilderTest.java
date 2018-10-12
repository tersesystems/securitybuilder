package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.PBEKey;
import org.junit.jupiter.api.Test;

public class PasswordBuilderTest {

  @Test
  public void testPasswordSpec() throws Exception {
    byte[] salt = randomSalt();

    PBEKey passwordBasedEncryptionKey = PasswordBuilder.builder()
        .withPBKDF2WithHmacSHA512()
        .withPassword("hello world".toCharArray())
        .withIterations(1000)
        .withSalt(salt)
        .withKeyLength(64 * 8)
        .build();

    byte[] encryptedPassword = passwordBasedEncryptionKey.getEncoded();
    assertThat(passwordBasedEncryptionKey.getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA512");
  }

  private byte[] randomSalt() {
    Random random = new SecureRandom();
    final byte[] bytes = new byte[256];
    random.nextBytes(bytes);
    return bytes;
  }
}
