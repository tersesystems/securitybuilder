package com.tersesystems.securitybuilder;

public class RuntimeKeyStoreException extends RuntimeException {

  public RuntimeKeyStoreException() {
  }

  public RuntimeKeyStoreException(final String message) {
    super(message);
  }

  public RuntimeKeyStoreException(final String message, final Throwable cause) {
    super(message, cause);
  }

  public RuntimeKeyStoreException(final Throwable cause) {
    super(cause);
  }

  public RuntimeKeyStoreException(
      final String message,
      final Throwable cause,
      final boolean enableSuppression,
      final boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
