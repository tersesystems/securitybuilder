package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;

public class PKCS8EncodedKeySpecBuilderTest {

  @Test
  public void testPrivateKey() throws Exception {
    // Read a private key
    final Reader reader = new InputStreamReader(getClass().getResourceAsStream("/private-key.pem"));
    final PKCS8EncodedKeySpec keySpec =
        PKCS8EncodedKeySpecBuilder.builder().withReader(reader).withNoPassword().build();
    assertThat(keySpec.getFormat()).isEqualTo("PKCS#8");
  }


  @Test
  public void testPublicKey() throws Exception {
    RSAKeyPair keyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).create();
    Signature signingSig = SignatureBuilder.builder().withSHA256withRSA().signing(keyPair.getPrivate()).build();

    byte[] someData = "hello world!".getBytes(StandardCharsets.UTF_8);
    signingSig.update(someData);
    byte[] signed = signingSig.sign();
    byte[] rawPublicBytes = keyPair.getPublic().getEncoded();

    // Assume only the raw bytes are available down here: the certificate and the signature show that the
    // data was signed by this signature...
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(rawPublicBytes);
    RSAPublicKey pubKey = PublicKeyBuilder.builder().withRSA().withKeySpec(pubKeySpec).build();

    // Should have some shortcuts for SHA256withRSA
    Signature verifyingSig = SignatureBuilder.builder().withSHA256withRSA().verifying(pubKey).build();
    verifyingSig.update(someData);

    assertThat(verifyingSig.verify(signed)).isTrue();
  }


}
