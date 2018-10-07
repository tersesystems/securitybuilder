package com.tersesystems.securitybuilder;

import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import org.jetbrains.annotations.NotNull;

public interface DSAKeyPair extends KeyPair<DSAPublicKey, DSAPrivateKey> {

  static DSAKeyPair create(@NotNull DSAPublicKey publicKey, @NotNull DSAPrivateKey privateKey) {
    return new DSAKeyPair() {
      @NotNull
      @Override
      public DSAPublicKey getPublic() {
        return publicKey;
      }

      @NotNull
      @Override
      public DSAPrivateKey getPrivate() {
        return privateKey;
      }
    };
  }

  static DSAKeyPair create(@NotNull java.security.KeyPair keyPair) {
    return new DSAKeyPair() {
      @NotNull
      @Override
      public DSAPublicKey getPublic() {
        return (DSAPublicKey) keyPair.getPublic();
      }

      @NotNull
      @Override
      public DSAPrivateKey getPrivate() {
        return (DSAPrivateKey) keyPair.getPrivate();
      }
    };
  }
}
