package com.tersesystems.securitybuilder;

import java.security.SecureRandom;
import sun.security.jca.JCAUtil;

/**
 * Provide a reasonable source of random bytes.
 */
public class EntropySource {

  // Always 12 in practice.
  public static final int DEFAULT_GCM_IV_LENGTH = 12;

  // https://crypto.stackexchange.com/a/34866 = 32 bytes (256 bits)
  // https://security.stackexchange.com/a/11224 = (128 bits is more than enough)
  public static final int DEFAULT_SALT_LENGTH = 32;

  /**
   * Provides an initialization vector for GCM.  This is always 12 bytes.
   *
   * You must NEVER reuse an IV.
   *
   * @return a byte array of random bytes.
   */
  public static byte[] gcmIV() {
    return nextBytes(DEFAULT_GCM_IV_LENGTH);
  }

  /**
   * Provides a salt, which must be unique but is not private.
   *
   * The default is 256 of random data from /dev/urandom, which is
   * more than enough for any reasonable purpose.
   *
   * @return a byte array of random bytes.
   */
  public static byte[] salt() {
    return nextBytes(DEFAULT_SALT_LENGTH);
  }

  private static final byte[] nextBytes(int length) {
    SecureRandom secureRandom = JCAUtil.getSecureRandom();
    byte[] bytes = new byte[length];
    secureRandom.nextBytes(bytes);
    return bytes;
  }
}
