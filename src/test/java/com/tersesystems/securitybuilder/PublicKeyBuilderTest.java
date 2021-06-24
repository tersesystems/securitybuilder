package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.interfaces.DHPublicKey;
import org.junit.jupiter.api.Test;

public class PublicKeyBuilderTest {

  @Test
  public void testWithAlgorithm() throws GeneralSecurityException {
    ECPublicKey pk = KeyPairCreator.creator().withEC().withKeySize(256).create().getPublic();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pk.getEncoded());
    PublicKey publicKey =
        PublicKeyBuilder.builder().withAlgorithm("EC").withKeySpec(keySpec).build();
    assertThat(Arrays.equals(pk.getEncoded(), publicKey.getEncoded())).isTrue();
  }

  @Test
  public void testRSAPublicKey() throws GeneralSecurityException {
    RSAPublicKey pk = KeyPairCreator.creator().withRSA().withKeySize(2048).create().getPublic();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pk.getEncoded());
    RSAPublicKey publicKey = PublicKeyBuilder.builder().withRSA().withKeySpec(keySpec).build();
    assertThat(Arrays.equals(pk.getEncoded(), publicKey.getEncoded())).isTrue();
  }

  @Test
  public void testECPublicKey() throws GeneralSecurityException {
    ECPublicKey pk = KeyPairCreator.creator().withEC().withKeySize(224).create().getPublic();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pk.getEncoded());
    ECPublicKey publicKey = PublicKeyBuilder.builder().withEC().withKeySpec(keySpec).build();
    assertThat(Arrays.equals(pk.getEncoded(), publicKey.getEncoded())).isTrue();
  }

  @Test
  public void testDSAPublicKey() throws GeneralSecurityException {
    DSAPublicKey pk = KeyPairCreator.creator().withDSA().withKeySize(1024).create().getPublic();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pk.getEncoded());
    DSAPublicKey publicKey = PublicKeyBuilder.builder().withDSA().withKeySpec(keySpec).build();
    assertThat(Arrays.equals(pk.getEncoded(), publicKey.getEncoded())).isTrue();
  }

  @Test
  public void testDHPublicKey() throws GeneralSecurityException {
    DHPublicKey pk = KeyPairCreator.creator().withDH().withKeySize(1024).create().getPublic();
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pk.getEncoded());
    DHPublicKey publicKey = PublicKeyBuilder.builder().withDH().withKeySpec(keySpec).build();
    assertThat(Arrays.equals(pk.getEncoded(), publicKey.getEncoded())).isTrue();
  }
}
