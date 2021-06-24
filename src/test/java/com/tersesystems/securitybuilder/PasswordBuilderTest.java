package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import javax.crypto.interfaces.PBEKey;
import org.junit.jupiter.api.Test;

public class PasswordBuilderTest {

  @Test
  public void testPasswordSpec() throws Exception {
    byte[] salt = EntropySource.salt();

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
}
