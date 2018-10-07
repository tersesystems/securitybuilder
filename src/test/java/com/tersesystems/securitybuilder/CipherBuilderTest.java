package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class CipherBuilderTest {

  @Test
  public void testCipher() throws GeneralSecurityException {
    // calls getInstance and then inits the cipher.
    byte[] keyBytes = MessageDigest.getInstance("MD5").digest("som3C0o7p@s5".getBytes());
    Key key = new SecretKeySpec(keyBytes, "AES");
    Cipher cipher = CipherBuilder.builder().withTransformation("AES/GCM/NoPadding").withEncrypt(key).build();

    assertThat(cipher.getAlgorithm()).isEqualTo("AES/GCM/NoPadding");
  }

}