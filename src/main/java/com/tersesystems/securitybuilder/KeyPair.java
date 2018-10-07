package com.tersesystems.securitybuilder;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

public interface KeyPair<PBK extends PublicKey, PVK extends PrivateKey> {

  PBK getPublic();

  PVK getPrivate();

  @NotNull
  @Contract(pure = true)
  default java.security.KeyPair getKeyPair() {
    return new java.security.KeyPair(getPublic(), getPrivate());
  }

  static <PBK extends PublicKey, PVK extends PrivateKey> KeyPair<PBK, PVK> create(
      @NotNull java.security.KeyPair keyPair) {
    return new KeyPair<PBK, PVK>() {

      @NotNull
      @Override
      public PBK getPublic() {
        return (PBK) keyPair.getPublic();
      }

      @NotNull
      @Override
      public PVK getPrivate() {
        return (PVK) keyPair.getPrivate();
      }
    };
  }
}
