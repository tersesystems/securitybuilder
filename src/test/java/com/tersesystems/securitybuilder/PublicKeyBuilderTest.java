package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class PublicKeyBuilderTest {

  @Test
  public void testRSAPublicKey() throws GeneralSecurityException {
    final BigInteger modulus =
        new BigInteger(
            "b4a7e46170574f16a97082b22be58b6a2a629798419"
                + "be12872a4bdba626cfae9900f76abfb12139dce5de5"
                + "6564fab2b6543165a040c606887420e33d91ed7ed7",
            16);
    final BigInteger exp = new BigInteger("11", 16);
    final RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exp);
    RSAPublicKey rsaPublicKey =
        PublicKeyBuilder.builder().withRSA().withKeySpec(rsaPublicKeySpec).build();
    assertThat(rsaPublicKey).isNotNull();
  }

  @Test
  public void testECPublicKey() throws GeneralSecurityException {
    byte[] publicX =
        new BigInteger("89c048261979208666f2bfb188be1968fc9021c416ce12828c06f4e314c167b5", 16)
            .toByteArray();
    byte[] publicY =
        new BigInteger("cbf1eb7587f08e01688d9ada4be859137ca49f79394bad9179326b3090967b68", 16)
            .toByteArray();
    // Get Elliptic Curve Parameter spec for secp256r1
    AlgorithmParameters algoParameters = AlgorithmParameters.getInstance("EC");
    algoParameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec parameterSpec = algoParameters.getParameterSpec(ECParameterSpec.class);

    // Create key specs
    ECPublicKeySpec publicKeySpec =
        new ECPublicKeySpec(
            new ECPoint(new BigInteger(publicX), new BigInteger(publicY)), parameterSpec);
    ECPublicKey publicKey = PublicKeyBuilder.builder().withEC().withKeySpec(publicKeySpec).build();
    assertThat(publicKey).isNotNull();
  }

  @Test
  public void testDSAPublicKey() throws GeneralSecurityException {
    java.security.KeyPairGenerator dsa = java.security.KeyPairGenerator.getInstance("DSA");
    dsa.initialize(1024);
    KeyPair keyPair = dsa.generateKeyPair();
    DSAPublicKey pk = (DSAPublicKey) keyPair.getPublic();

    // Create key specs
    DSAPublicKeySpec publicKeySpec =
        new DSAPublicKeySpec(
            pk.getY(), pk.getParams().getP(), pk.getParams().getQ(), pk.getParams().getG());
    DSAPublicKey publicKey =
        PublicKeyBuilder.builder().withDSA().withKeySpec(publicKeySpec).build();
    assertThat(publicKey).isNotNull();
  }


  @Test
  public void testX509EncodedKeySpec() {
    try {
      final ECKeyPair keyPair =
          KeyPairCreator.creator().withEC().withKeySize(256).create();
      final ECPublicKey publicKey = keyPair.getPublic();
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getEncoded());

      final ECPublicKey otherPublicKey = PublicKeyBuilder.builder().withEC().withKeySpec(keySpec)
          .build();

      assertThat(Arrays.equals(publicKey.getEncoded(), otherPublicKey.getEncoded())).isTrue();
    } catch (GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }
}
