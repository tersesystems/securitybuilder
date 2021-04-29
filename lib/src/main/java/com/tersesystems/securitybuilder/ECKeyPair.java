package com.tersesystems.securitybuilder;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * A type safe keypair for ECPublicKey and ECPrivateKey.
 */
public interface ECKeyPair extends KeyPair<ECPublicKey, ECPrivateKey> {


  static ECKeyPair create(ECPublicKey publicKey, ECPrivateKey privateKey) {
    return new ECKeyPair() {

      @Override
      public ECPublicKey getPublic() {
        return publicKey;
      }


      @Override
      public ECPrivateKey getPrivate() {
        return privateKey;
      }
    };
  }


  @SuppressWarnings("unchecked")
  static ECKeyPair create(java.security.KeyPair keyPair) {
    return new ECKeyPair() {

      @Override
      public ECPublicKey getPublic() {
        return (ECPublicKey) keyPair.getPublic();
      }


      @Override
      public ECPrivateKey getPrivate() {
        return (ECPrivateKey) keyPair.getPrivate();
      }
    };
  }
}
