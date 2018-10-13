package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class KeyAgreementBuilderTest {

  @Test
  public void testKeyAgreement() throws GeneralSecurityException {
    ECKeyPair kp = KeyPairCreator.creator().withEC().withKeySize(256).create();
    KeyAgreement keyAgreement = KeyAgreementBuilder.builder()
        .withECDH()
        .withKey(kp.getPrivate())
        .build();

    assertThat(keyAgreement.getAlgorithm()).isEqualTo("ECDH");
  }

  @Test
  public void testKeyAgreementParams() throws GeneralSecurityException, IOException {
    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex

    // Alice creates her own DH key pair with 2048-bit key size
    DHKeyPair aliceKpair = KeyPairCreator.creator().withDH().withKeySize(2048).create();

    // Alice creates and initializes her DH KeyAgreement object
    KeyAgreement aliceKeyAgree = KeyAgreementBuilder.builder()
        .withDH()
        .withKey(aliceKpair.getPrivate())
        .build();

    // Alice encodes her public key, and sends it over to Bob.
    byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

    //* Let's turn over to Bob. Bob has received Alice's public key
    //* in encoded format.
    //* He instantiates a DH public key from the encoded key material.
    DHPublicKey alicePubKey = PublicKeyBuilder.builder().withDH()
        .withKeySpec(new X509EncodedKeySpec(alicePubKeyEnc)).build();

    //* Bob gets the DH parameters associated with Alice's public key.
    //* He must use the same parameters when he generates his own key
    //* pair.
    DHParameterSpec dhParamFromAlicePubKey = alicePubKey.getParams();

    // Bob creates his own DH key pair
    DHKeyPair bobKpair = KeyPairCreator.creator().withDH().withKeySpec(dhParamFromAlicePubKey)
        .create();

    // Bob creates and initializes his DH KeyAgreement object
    KeyAgreement bobKeyAgree = KeyAgreementBuilder.builder().withDH().withKey(bobKpair.getPrivate())
        .build();

    // Bob encodes his public key, and sends it over to Alice.
    byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

    //* Alice uses Bob's public key for the first (and only) phase
    //* of her version of the DH protocol.
    //* Before she can do so, she has to instantiate a DH public key
    //* from Bob's encoded key material.
    DHPublicKey bobPubKey = PublicKeyBuilder.builder().withDH()
        .withKeySpec(new X509EncodedKeySpec(bobPubKeyEnc)).build();
    aliceKeyAgree.doPhase(bobPubKey, true);

    //* Bob uses Alice's public key for the first (and only) phase
    //* of his version of the DH protocol.
    bobKeyAgree.doPhase(alicePubKey, true);

    // At this stage, both Alice and Bob have completed the DH key
    // agreement protocol. Both generate the (same) shared secret.
    byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
    byte[] bobSharedSecret = new byte[aliceSharedSecret.length];
    bobKeyAgree.generateSecret(bobSharedSecret, 0);
    assertThat(Arrays.equals(aliceSharedSecret, bobSharedSecret)).isTrue();

    // Now let's create a SecretKey object using the shared secret
    // and use it for encryption.
    SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
    SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

    // Bob encrypts, using AES in GCM mode
    final byte[] iv = EntropySource.gcmIV();
    Cipher bobCipher = AuthenticatedEncryptionBuilder.builder().withSecretKey(bobAesKey).withIv(iv)
        .encrypt();
    byte[] cleartext = "This is just an example".getBytes();
    byte[] ciphertext = bobCipher.doFinal(cleartext);

    // Alice decrypts, using AES in GCM mode
    Cipher aliceCipher = AuthenticatedEncryptionBuilder.builder().withSecretKey(aliceAesKey).withIv(iv).decrypt();
    byte[] recovered = aliceCipher.doFinal(ciphertext);
    assertThat(Arrays.equals(cleartext, recovered)).isTrue();
  }

  /*
   * Converts a byte to hex digit and writes to the supplied buffer
   */
  private static void byte2hex(byte b, StringBuffer buf) {
    char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    int high = ((b & 0xf0) >> 4);
    int low = (b & 0x0f);
    buf.append(hexChars[high]);
    buf.append(hexChars[low]);
  }

  /*
   * Converts a byte array to hex string
   */
  private static String toHexString(byte[] block) {
    StringBuffer buf = new StringBuffer();
    int len = block.length;
    for (int i = 0; i < len; i++) {
      byte2hex(block[i], buf);
      if (i < len - 1) {
        buf.append(":");
      }
    }
    return buf.toString();
  }
}
