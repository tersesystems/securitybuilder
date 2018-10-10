package com.tersesystems.securitybuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

public class KeyStoreDefaults {

  private KeyStoreDefaults() {
  }

  // https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#CustomizingStores
  // https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#T6
  // If the javax.net.ssl.keyStoreType and/or javax.net.ssl.keyStorePassword system properties are
  // also specified,
  // then they are treated as the default KeyManager keystore type and password, respectively.
  // If no type is specified, then the default type is that returned by the
  // KeyStore.getDefaultType() method,
  // which is the value of the keystore.type security property, or "jks" if no such security
  // property is specified.
  // If no keystore password is specified, then it is assumed to be a blank string "".
  // From sun.security.ssl.SSLContextImpl

  public static KeyStore getKeyStore() throws Exception {
    final String NONE = "NONE";

    final Map<String, String> props = new HashMap<>();
    AccessController.doPrivileged(
        (PrivilegedExceptionAction<Object>)
            () -> {
              props.put("getKeyStore", System.getProperty("javax.net.ssl.getKeyStore", ""));
              props.put(
                  "keyStoreType",
                  System.getProperty("javax.net.ssl.keyStoreType", KeyStore.getDefaultType()));
              props.put(
                  "keyStoreProvider", System.getProperty("javax.net.ssl.keyStoreProvider", ""));
              props.put("keyStorePasswd", System.getProperty("javax.net.ssl.keyStorePassword", ""));
              return null;
            });

    final String defaultKeyStore = props.get("getKeyStore");
    final String defaultKeyStoreType = props.get("keyStoreType");
    final String defaultKeyStoreProvider = props.get("keyStoreProvider");

    InputStream fs = null;
    KeyStore ks = null;
    char[] passwd = null;
    try {
      if (defaultKeyStore.length() != 0 && !NONE.equals(defaultKeyStore)) {
        FileSystem fileSystem = FileSystems.getDefault();
        fs =
            AccessController.doPrivileged(
                (PrivilegedExceptionAction<InputStream>)
                    () -> Files.newInputStream(fileSystem.getPath(defaultKeyStore)));
      }

      final String defaultKeyStorePassword = props.get("keyStorePasswd");
      if (defaultKeyStorePassword.length() != 0) {
        passwd = defaultKeyStorePassword.toCharArray();
      }

      /* Try to initialize key store. */
      if ((defaultKeyStoreType.length()) != 0) {
        if (defaultKeyStoreProvider.length() == 0) {
          ks = KeyStore.getInstance(defaultKeyStoreType);
        } else {
          ks = KeyStore.getInstance(defaultKeyStoreType, defaultKeyStoreProvider);
        }

        // if defaultKeyStore is NONE, fs will be null
        ks.load(fs, passwd);
      }

      return (ks == null) ? KeyStoreBuilder.empty() : ks;
    } finally {
      if (fs != null) {
        fs.close();
        fs = null;
      }
    }
  }

  // From sun.security.ssl.TrustManagerFactoryImpl

  public static KeyStore getCacertsKeyStore() throws Exception {
    String storeFileName = null;
    File storeFile = null;
    FileInputStream fis = null;
    final String defaultTrustStoreType;
    final String defaultTrustStoreProvider;
    final HashMap<String, String> props = new HashMap<>();
    final String sep = File.separator;
    KeyStore ks = null;

    AccessController.doPrivileged(
        (PrivilegedExceptionAction<Void>)
            () -> {
              props.put("trustStore", System.getProperty("javax.net.ssl.trustStore"));
              props.put("javaHome", System.getProperty("java.home"));
              props.put(
                  "trustStoreType",
                  System.getProperty("javax.net.ssl.trustStoreType", KeyStore.getDefaultType()));
              props.put(
                  "trustStoreProvider", System.getProperty("javax.net.ssl.trustStoreProvider", ""));
              props.put(
                  "trustStorePasswd", System.getProperty("javax.net.ssl.trustStorePassword", ""));
              return null;
            });

    /*
     * Try:
     *      javax.net.ssl.trustStore  (if this variable exists, stop)
     *      jssecacerts
     *      cacerts
     *
     * If none exists, we use an empty keystore.
     */

    try {
      storeFileName = props.get("trustStore");
      if (!"NONE".equals(storeFileName)) {
        if (storeFileName != null) {
          storeFile = new File(storeFileName);
          fis = getFileInputStream(storeFile);
        } else {
          final String javaHome = props.get("javaHome");
          storeFile = new File(javaHome + sep + "lib" + sep + "security" + sep + "jssecacerts");
          if ((fis = getFileInputStream(storeFile)) == null) {
            storeFile = new File(javaHome + sep + "lib" + sep + "security" + sep + "cacerts");
            fis = getFileInputStream(storeFile);
          }
        }

        if (fis != null) {
          storeFileName = storeFile.getPath();
        } else {
          storeFileName = "No File Available, using empty keystore.";
        }
      }

      defaultTrustStoreType = props.get("trustStoreType");
      defaultTrustStoreProvider = props.get("trustStoreProvider");

      /*
       * Try to initialize trust store.
       */
      if (defaultTrustStoreType.length() != 0) {
        if (defaultTrustStoreProvider.length() == 0) {
          ks = KeyStore.getInstance(defaultTrustStoreType);
        } else {
          ks = KeyStore.getInstance(defaultTrustStoreType, defaultTrustStoreProvider);
        }
        char[] passwd = null;
        final String defaultTrustStorePassword = props.get("trustStorePasswd");
        if (defaultTrustStorePassword.length() != 0) {
          passwd = defaultTrustStorePassword.toCharArray();
        }

        // if trustStore is NONE, fis will be null
        ks.load(fis, passwd);

        // Zero out the temporary password storage
        if (passwd != null) {
          for (int i = 0; i < passwd.length; i++) {
            passwd[i] = (char) 0;
          }
        }
      }
    } finally {
      if (fis != null) {
        fis.close();
      }
    }

    return (ks == null) ? KeyStoreBuilder.empty() : ks;
  }

  /*
   * Try to get an InputStream based on the file we pass in.
   */

  private static FileInputStream getFileInputStream(final File file) throws Exception {
    return AccessController.doPrivileged(
        new PrivilegedExceptionAction<FileInputStream>() {

          @Override
          public FileInputStream run() throws Exception {
            try {
              if (file.exists()) {
                return new FileInputStream(file);
              } else {
                return null;
              }
            } catch (final FileNotFoundException e) {
              // couldn't find it, oh well.
              return null;
            }
          }
        });
  }
}
