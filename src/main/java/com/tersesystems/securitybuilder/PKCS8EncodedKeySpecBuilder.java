package com.tersesystems.securitybuilder;

import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static javax.crypto.Cipher.DECRYPT_MODE;

import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.slieb.throwables.SupplierWithThrowable;

public class PKCS8EncodedKeySpecBuilder {

  // optional keyPassword
  public static final Pattern KEY_PATTERN =
      Pattern.compile(
          "-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+"
              + // Header
              "([a-z0-9+/=\\r\\n]+)"
              + // Base64 text
              "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+", // Footer
          CASE_INSENSITIVE);

  private PKCS8EncodedKeySpecBuilder() {
  }

  public static ContentStage builder() {
    return new ContentStageImpl();
  }

  public interface ContentStage {

    PasswordStage withContent(String content);


    PasswordStage withReader(Reader reader);
  }

  public interface PasswordStage {

    BuildFinal withPassword(char[] password);


    BuildFinal withNoPassword();
  }

  public interface BuildFinal {

    PKCS8EncodedKeySpec build() throws Exception;
  }

  static class ContentStageImpl implements ContentStage {

    @Override
    public PasswordStage withContent(final String content) {
      return new PasswordStageImpl(
          () -> {
            final Matcher matcher = KEY_PATTERN.matcher(content);
            if (!matcher.find()) {
              throw new GeneralSecurityException("found no private key!");
            }
            return java.util.Base64.getMimeDecoder().decode(matcher.group(1));
          });
    }


    @Override
    public PasswordStage withReader(final Reader reader) {
      return new PasswordStageImpl(
          () -> {
            final char[] arr = new char[16 * 1024];
            final StringBuilder buffer = new StringBuilder();
            int numCharsRead;
            while ((numCharsRead = reader.read(arr, 0, arr.length)) != -1) {
              buffer.append(arr, 0, numCharsRead);
            }
            reader.close();
            final String content = buffer.toString();

            final Matcher matcher = KEY_PATTERN.matcher(content);
            if (!matcher.find()) {
              throw new GeneralSecurityException("found no private key!");
            }
            return java.util.Base64.getMimeDecoder().decode(matcher.group(1));
          });
    }
  }

  static class PasswordStageImpl implements PasswordStage {

    private final SupplierWithThrowable<byte[], Exception> supplier;

    PasswordStageImpl(final SupplierWithThrowable<byte[], Exception> supplier) {
      this.supplier = supplier;
    }


    @Override
    public BuildFinal withPassword(final char[] password) {
      return new BuildFinalImpl(
          () -> {
            final byte[] privateKeyBytes = supplier.getWithThrowable();
            final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo =
                new EncryptedPrivateKeyInfo(privateKeyBytes);

            final SecretKeyFactory keyFactory =
                SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
            final Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());

            final SecretKey secretKey = keyFactory.generateSecret(new PBEKeySpec(password));
            cipher.init(DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.getAlgParameters());

            return encryptedPrivateKeyInfo.getKeySpec(cipher);
          });
    }


    @Override
    public BuildFinal withNoPassword() {
      return new BuildFinalImpl(() -> new PKCS8EncodedKeySpec(supplier.getWithThrowable()));
    }
  }

  static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<PKCS8EncodedKeySpec, Exception> supplier;

    BuildFinalImpl(final SupplierWithThrowable<PKCS8EncodedKeySpec, Exception> supplier) {
      this.supplier = supplier;
    }


    @Override
    public PKCS8EncodedKeySpec build() throws Exception {
      return supplier.getWithThrowable();
    }
  }
}
