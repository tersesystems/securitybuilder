package com.tersesystems.securitybuilder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import org.junit.jupiter.api.Test;

public class KeyAgreementBuilderTest {

  @Test
  public void testKeyAgreement() throws GeneralSecurityException {
    ECKeyPair kp = KeyPairBuilder.builder().withEC().withKeySize(256).build();
    KeyAgreement keyAgreement = KeyAgreementBuilder.builder().withAlgorithm("ECDH").withKey(kp.getPrivate()).build();

    assertThat(keyAgreement.getAlgorithm()).isEqualTo("ECDH");
  }

  @Test
  public void testKeyAgreementParams() throws GeneralSecurityException {
    AlgorithmParameters params = AlgorithmParametersBuilder.builder().withAlgorithm("DH").withKeySize(2048).build();
    DHParameterSpec parameterSpec = params.getParameterSpec(DHParameterSpec.class);
    KeyPair kp = KeyPairBuilder.builder().withAlgorithm("DH").withKeySpec(parameterSpec).build();

    // DHKeyAgreement or ECDHKeyAgreement or P11KeyAgreement (DH) or P11ECDHKeyAgreement
    //DHParameterSpec is the only valid one, ECDHKeyAgreement does not take parameterSpec
    KeyAgreement keyAgreement = KeyAgreementBuilder.builder().withAlgorithm("DH").withKeyAndSpec(kp.getPrivate(), parameterSpec).build();

    assertThat(keyAgreement.getAlgorithm()).isEqualTo("DH");
  }

}
