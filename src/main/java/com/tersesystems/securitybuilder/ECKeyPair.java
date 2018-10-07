package com.tersesystems.securitybuilder;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import org.jetbrains.annotations.NotNull;

public interface ECKeyPair extends KeyPair<ECPublicKey, ECPrivateKey> {

  static ECKeyPair create(@NotNull ECPublicKey publicKey, @NotNull ECPrivateKey privateKey) {
    return new ECKeyPair() {
      @NotNull
      @Override
      public ECPublicKey getPublic() {
        return publicKey;
      }

      @NotNull
      @Override
      public ECPrivateKey getPrivate() {
        return privateKey;
      }
    };
  }

  @SuppressWarnings("unchecked")
  static ECKeyPair create(@NotNull java.security.KeyPair keyPair) {
    return new ECKeyPair() {
      @NotNull
      @Override
      public ECPublicKey getPublic() {
        return (ECPublicKey) keyPair.getPublic();
      }

      @NotNull
      @Override
      public ECPrivateKey getPrivate() {
        return (ECPrivateKey) keyPair.getPrivate();
      }
    };
  }
}
