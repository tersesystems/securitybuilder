package com.tersesystems.securitybuilder;

import static java.security.MessageDigest.getInstance;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestBuilder {

  public static MessageDigest md2() throws NoSuchAlgorithmException {
    return getInstance("MD2");
  }

  public static MessageDigest md5() throws NoSuchAlgorithmException {
    return getInstance("MD5");
  }

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
