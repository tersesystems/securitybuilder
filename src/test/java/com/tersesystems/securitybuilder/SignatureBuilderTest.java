package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.assertj.core.api.Fail;
import org.junit.jupiter.api.Test;

public class SignatureBuilderTest {

  @Test
  public void testSignature() {
    try {
      final KeyPair<?, ?> keyPair =
          KeyPairBuilder.builder().withAlgorithm("RSA").withKeySize(2048).build();
      final PrivateKey privateKey = keyPair.getPrivate();
      final PublicKey publicKey = keyPair.getPublic();

      final Signature signingSignature =
          SignatureBuilder.builder().withAlgorithm("SHA256withRSA").signing(privateKey).build();
      final byte[] digest = signingSignature.sign();

      final Signature verifySignature =
          SignatureBuilder.builder().withAlgorithm("SHA256withRSA").verifying(publicKey).build();
      assertThat(verifySignature.verify(digest)).isEqualTo(true);
    } catch (final Exception e) {
      Fail.fail(e.getMessage(), e);
    }
  }

  @Test
  public void testRSignature() {
    try {
      final ECKeyPair keyPair =
          KeyPairBuilder.builder().withEC().withKeySize(256).build();
      final ECPrivateKey privateKey = keyPair.getPrivate();
      final ECPublicKey publicKey = keyPair.getPublic();

      byte[] data = "derp".getBytes(StandardCharsets.UTF_8);

      final Signature signingSignature =
          SignatureBuilder.builder().withSHA256withECDSA().signing(privateKey).build();
      signingSignature.update(data);
      final byte[] digest = signingSignature.sign();

      final Signature verifySignature =
          SignatureBuilder.builder().withSHA256withECDSA().verifying(publicKey).build();
      verifySignature.update(data);

      assertThat(verifySignature.verify(digest)).isEqualTo(true);
    } catch (final Exception e) {
      Fail.fail(e.getMessage(), e);
    }
  }


}
