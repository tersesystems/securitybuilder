package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.Test;

public class KeyAgreementBuilderTest {

  @Test
  public void testKeyAgreement() throws GeneralSecurityException {
    ECKeyPair kp = KeyPairCreator.creator().withEC().withKeySize(256).build();
    KeyAgreement keyAgreement = KeyAgreementBuilder.builder().withAlgorithm("ECDH").withKey(kp.getPrivate()).build();

    assertThat(keyAgreement.getAlgorithm()).isEqualTo("ECDH");
  }

  @Test
  public void testKeyAgreementParams() throws GeneralSecurityException {
    AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance("DH");
    generator.init(1024);
    AlgorithmParameters params = generator.generateParameters();
    DHParameterSpec parameterSpec = params.getParameterSpec(DHParameterSpec.class);
    KeyPair kp = KeyPairCreator.creator().withAlgorithm("DH").withKeySpec(parameterSpec).build();

    // DHKeyAgreement or ECDHKeyAgreement or P11KeyAgreement (DH) or P11ECDHKeyAgreement
    //DHParameterSpec is the only valid one, ECDHKeyAgreement does not take parameterSpec
    KeyAgreement keyAgreement = KeyAgreementBuilder.builder().withAlgorithm("DH").withKeyAndSpec(kp.getPrivate(), parameterSpec).build();

    assertThat(keyAgreement.getAlgorithm()).isEqualTo("DH");
  }

}
