package com.tersesystems.securitybuilder;


import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;
import org.slieb.throwables.SupplierWithThrowable;

public class CipherBuilder {

  public interface InitialStage {

    ModeStage withTransformation(String transformation);

    ModeStage withTransformationAndProvider(String algorithm, String provider);
  }

  public interface ModeStage {

    BuildFinal withEncrypt(Key key);

    BuildFinal withDecrypt(Key key);

    BuildFinal withWrap(Key key);

    BuildFinal withUnwrap(Key key);
  }

  public interface BuildFinal {

    Cipher build() throws GeneralSecurityException;
  }

  static class InitialStageImpl implements InitialStage {

    @Override
    public ModeStage withTransformation(final String transformation) {
      return new ModeStageImpl(() -> Cipher.getInstance(transformation));
    }

    @Override
    public ModeStage withTransformationAndProvider(final String transformation,
        final String provider) {
      return new ModeStageImpl(() -> Cipher.getInstance(transformation, provider));
    }
  }

  static class ModeStageImpl implements ModeStage {

    private final SupplierWithThrowable<Cipher, GeneralSecurityException> supplier;

    ModeStageImpl(SupplierWithThrowable<Cipher, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public BuildFinal withEncrypt(final Key key) {
      return new BuildFinalImpl(() -> {
        Cipher cipher = supplier.getWithThrowable();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
      });
    }

    @Override
    public BuildFinal withDecrypt(final Key key) {
      return new BuildFinalImpl(() -> {
        Cipher cipher = supplier.getWithThrowable();
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher;
      });
    }

    @Override
    public BuildFinal withWrap(final Key key) {
      return new BuildFinalImpl(() -> {
        Cipher cipher = supplier.getWithThrowable();
        cipher.init(Cipher.WRAP_MODE, key);
        return cipher;
      });
    }

    @Override
    public BuildFinal withUnwrap(final Key key) {
      return new BuildFinalImpl(() -> {
        Cipher cipher = supplier.getWithThrowable();
        cipher.init(Cipher.UNWRAP_MODE, key);
        return cipher;
      });
    }
  }

  static class BuildFinalImpl implements BuildFinal {

    private final SupplierWithThrowable<Cipher, GeneralSecurityException> supplier;

    BuildFinalImpl(
        final SupplierWithThrowable<Cipher, GeneralSecurityException> supplier) {
      this.supplier = supplier;
    }

    @Override
    public Cipher build() throws GeneralSecurityException {
      return supplier.getWithThrowable();
    }
  }

  public static InitialStage builder() {
    return new InitialStageImpl();
  }

}
