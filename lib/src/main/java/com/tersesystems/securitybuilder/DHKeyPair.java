package com.tersesystems.securitybuilder;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

/**
 * A type safe keypair for DHPublicKey and DHPrivateKey.
 */
public interface DHKeyPair extends KeyPair<DHPublicKey, DHPrivateKey> {


  static DHKeyPair create(DHPublicKey publicKey, DHPrivateKey privateKey) {
    return new DHKeyPair() {

      @Override
      public DHPublicKey getPublic() {
        return publicKey;
      }


      @Override
      public DHPrivateKey getPrivate() {
        return privateKey;
      }
    };
  }


  static DHKeyPair create(java.security.KeyPair keyPair) {
    return new DHKeyPair() {

      @Override
      public DHPublicKey getPublic() {
        return (DHPublicKey) keyPair.getPublic();
      }


      @Override
      public DHPrivateKey getPrivate() {
        return (DHPrivateKey) keyPair.getPrivate();
      }
    };
  }
}
