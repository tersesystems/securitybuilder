package com.tersesystems.securitybuilder;

import static java.util.Objects.requireNonNull;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Creates a symmetric cipher builder, using AES/GCM/NoPadding.
 *
 * See <a href="https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/">How
 * to choose an Authenticated Encryption mode</a> for why you want this.
 */
public class AuthenticatedEncryptionBuilder {
  // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
  // https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher
  // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SimpleEncrEx

  public static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
  public static final int TAG_LENGTH = 128;

  public static InitialStage builder() {
    return new InitialStageImpl();
  }

  public interface InitialStage {

    IvStage withSecretKey(SecretKey key);
  }

  public interface IvStage {

    ModeStage withIv(final byte[] iv);
  }

  public interface ModeStage {

    Cipher encrypt() throws GeneralSecurityException;

    Cipher decrypt() throws GeneralSecurityException;
  }

  private static class InitialStageImpl implements InitialStage {

    @Override
    public IvStage withSecretKey(final SecretKey key) {
      requireNonNull(key, "SecretKey must not be null!");
      if (!key.getAlgorithm().equals("AES")) {
        throw new IllegalStateException("SecretKey algorithm must equal AES!");
      }
      return new IvStageImpl(key);
    }
  }

  private static class IvStageImpl implements IvStage {

    private final SecretKey key;

    IvStageImpl(final SecretKey key) {
      this.key = key;
    }

    @Override
    public ModeStage withIv(final byte[] iv) {
      requireNonNull(iv, "Initialization vector must not be null!");
      if (iv.length != EntropySource.DEFAULT_GCM_IV_LENGTH) {
        throw new IllegalStateException(
            "Initialization vector must be 12 bytes from SecureRandom!");
      }
      return new ModeStageImpl(key, iv);
    }
  }

  private static class ModeStageImpl implements ModeStage {

    private final SecretKey key;
    private final byte[] iv;

    ModeStageImpl(final SecretKey key, final byte[] iv) {
      this.key = key;
      this.iv = iv;
    }

    @Override
    public Cipher encrypt() throws GeneralSecurityException {
      Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));
      return cipher;
    }

    @Override
    public Cipher decrypt() throws GeneralSecurityException {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));
      return cipher;
    }
  }

}
