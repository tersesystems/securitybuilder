package com.tersesystems.securitybuilder;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyPair<PBK extends PublicKey, PVK extends PrivateKey> {

  static <PBK extends PublicKey, PVK extends PrivateKey> KeyPair<PBK, PVK> create(
      java.security.KeyPair keyPair) {
    return new KeyPair<PBK, PVK>() {


      @Override
      @SuppressWarnings("unchecked")
      public PBK getPublic() {
        return (PBK) keyPair.getPublic();
      }


      @Override

      @SuppressWarnings("unchecked")
      public PVK getPrivate() {
        return (PVK) keyPair.getPrivate();
      }
    };
  }

  PBK getPublic();

  PVK getPrivate();

  default java.security.KeyPair getKeyPair() {
    return new java.security.KeyPair(getPublic(), getPrivate());
  }
}
