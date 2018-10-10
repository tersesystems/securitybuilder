package com.tersesystems.securitybuilder;

import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

public interface DSAKeyPair extends KeyPair<DSAPublicKey, DSAPrivateKey> {


  static DSAKeyPair create(DSAPublicKey publicKey, DSAPrivateKey privateKey) {
    return new DSAKeyPair() {

      @Override
      public DSAPublicKey getPublic() {
        return publicKey;
      }


      @Override
      public DSAPrivateKey getPrivate() {
        return privateKey;
      }
    };
  }


  static DSAKeyPair create(java.security.KeyPair keyPair) {
    return new DSAKeyPair() {

      @Override
      public DSAPublicKey getPublic() {
        return (DSAPublicKey) keyPair.getPublic();
      }


      @Override
      public DSAPrivateKey getPrivate() {
        return (DSAPrivateKey) keyPair.getPrivate();
      }
    };
  }
}
