package com.tersesystems.securitybuilder;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.tersesystems.securitybuilder.AuthenticatedEncryptionBuilder.IvStage;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class AuthenticatedEncryptionBuilderTest {
  @Test
  public void testCipher() throws GeneralSecurityException {
    // You always want to use AES/GCM because reasons:
    // https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/

    final SecretKey aesSecretKey = SecretKeyGenerator.generate().withAES().withKeySize(128).build();
    final SecretKeySpec secretKeySpec =
        new SecretKeySpec(aesSecretKey.getEncoded(), aesSecretKey.getAlgorithm());
    IvStage builder = AuthenticatedEncryptionBuilder.builder().withSecretKey(secretKeySpec);

    byte[] gcmIV = EntropySource.gcmIV();
    byte[] inputData = "input text".getBytes(UTF_8);

    byte[] encryptedData = builder.withIv(gcmIV).encrypt().doFinal(inputData);
    byte[] decryptedData = builder.withIv(gcmIV).decrypt().doFinal(encryptedData);

    String decryptString = new String(decryptedData, UTF_8);
    assertThat(decryptString).isEqualTo("input text");
  }
}
