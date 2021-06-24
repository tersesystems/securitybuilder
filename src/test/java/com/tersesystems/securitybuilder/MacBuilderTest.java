package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class MacBuilderTest {

  @Test
  void testMacBuild() throws GeneralSecurityException {
    SecretKey key = new SecretKeySpec("privatekey".getBytes(), "HmacSHA256");

    Mac sha256Mac = MacBuilder.builder().withAlgorithm("HmacSHA256").withKey(key).build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));

    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output)
        .isEqualTo("27f0d5331806fb9f21247b19bee883a7cfe54c069d6e28edccc2cff8e78c4a74");
  }

  @Test
  void testSecretKeySpec() throws GeneralSecurityException {
    Mac sha256Mac =
        MacBuilder.builder().withSecretKeySpec("HmacSHA256").withString("privatekey").build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));

    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output)
        .isEqualTo("27f0d5331806fb9f21247b19bee883a7cfe54c069d6e28edccc2cff8e78c4a74");
  }

  @Test
  void testHmac() throws GeneralSecurityException {
    Mac sha256Mac = MacBuilder.builder().withHmacSHA256().withString("privatekey").build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));

    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output)
        .isEqualTo("27f0d5331806fb9f21247b19bee883a7cfe54c069d6e28edccc2cff8e78c4a74");
  }

  static String byteArrayToHex(byte[] a) {
    StringBuilder sb = new StringBuilder(a.length * 2);
    for (byte b : a) sb.append(String.format("%02x", b));
    return sb.toString();
  }
}
