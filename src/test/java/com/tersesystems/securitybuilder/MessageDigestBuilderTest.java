package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

public class MessageDigestBuilderTest {

  @Test
  public void testMD2() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.md2().getAlgorithm()).isEqualTo("MD2");
  }

  @Test
  public void testMD5() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.md5().getAlgorithm()).isEqualTo("MD5");
  }

  @Test
  public void testSha1() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.sha1().getAlgorithm()).isEqualTo("SHA-1");
  }

  @Test
  public void testSha224() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.sha224().getAlgorithm()).isEqualTo("SHA-224");
  }

  @Test
  public void testSha256() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.sha256().getAlgorithm()).isEqualTo("SHA-256");
  }

  @Test
  public void testSha384() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.sha384().getAlgorithm()).isEqualTo("SHA-384");
  }

  @Test
  public void testSha512() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.sha512().getAlgorithm()).isEqualTo("SHA-512");
  }
}
