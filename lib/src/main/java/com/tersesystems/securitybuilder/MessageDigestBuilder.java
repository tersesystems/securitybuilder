package com.tersesystems.securitybuilder;

import static java.security.MessageDigest.getInstance;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Generates some handy message digests.
 */
public class MessageDigestBuilder {

  /**
   * You should not be using SHA1.
   *
   * @deprecated https://blog.qualys.com/ssllabs/2014/09/09/sha1-deprecation-what-you-need-to-know
   * @return a MessageDigest configured for SHA-1.
   */
  @Deprecated
  public static MessageDigest sha1() throws NoSuchAlgorithmException {
    return getInstance("SHA-1");
  }

  public static MessageDigest sha224() throws NoSuchAlgorithmException {
    return getInstance("SHA-224");
  }

  public static MessageDigest sha256() throws NoSuchAlgorithmException {
    return getInstance("SHA-256");
  }

  public static MessageDigest sha384() throws NoSuchAlgorithmException {
    return getInstance("SHA-384");
  }

  public static MessageDigest sha512() throws NoSuchAlgorithmException {
    return getInstance("SHA-512");
  }
}
