package com.tersesystems.securitybuilder;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.jetbrains.annotations.NotNull;

public interface RSAKeyPair extends KeyPair<RSAPublicKey, RSAPrivateKey> {

  static RSAKeyPair create(@NotNull RSAPublicKey publicKey, @NotNull RSAPrivateKey privateKey) {
    return new RSAKeyPair() {
      @NotNull
      @Override
      public RSAPublicKey getPublic() {
        return publicKey;
      }

      @NotNull
      @Override
      public RSAPrivateKey getPrivate() {
        return privateKey;
      }
    };
  }

  static RSAKeyPair create(@NotNull java.security.KeyPair keyPair) {
    return new RSAKeyPair() {
      @NotNull
      @Override
      public RSAPublicKey getPublic() {
        return (RSAPublicKey) keyPair.getPublic();
      }

      @NotNull
      @Override
      public RSAPrivateKey getPrivate() {
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    };
  }
}
