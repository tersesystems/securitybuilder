package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStreamReader;
import java.io.Reader;
import java.security.spec.PKCS8EncodedKeySpec;
import org.junit.jupiter.api.Test;

class PKCS8EncodedKeySpecBuilderTest {

  @Test
  public void testGeneration() throws Exception {
    // Read a private key
    final Reader reader = new InputStreamReader(getClass().getResourceAsStream("/private-key.pem"));
    final PKCS8EncodedKeySpec keySpec =
        PKCS8EncodedKeySpecBuilder.builder().withReader(reader).withNoPassword().build();
    assertThat(keySpec.getFormat()).isEqualTo("PKCS#8");
  }
}
