package com.tersesystems.securitybuilder;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/** A type safe keypair for RSAPublicKey and RSAPrivateKey. */
public interface RSAKeyPair extends KeyPair<RSAPublicKey, RSAPrivateKey> {

  static RSAKeyPair create(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
    return new RSAKeyPair() {

      @Override
      public RSAPublicKey getPublic() {
        return publicKey;
      }

      @Override
      public RSAPrivateKey getPrivate() {
        return privateKey;
      }
    };
  }

  static RSAKeyPair create(java.security.KeyPair keyPair) {
    return new RSAKeyPair() {

      @Override
      public RSAPublicKey getPublic() {
        return (RSAPublicKey) keyPair.getPublic();
      }

      @Override
      public RSAPrivateKey getPrivate() {
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    };
  }
}
