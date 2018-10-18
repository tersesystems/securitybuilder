[ ![Download](https://api.bintray.com/packages/tersesystems/maven/securitybuilder/images/download.svg) ](https://bintray.com/tersesystems/maven/securitybuilder/_latestVersion) [![Build Status](https://travis-ci.org/tersesystems/securitybuilder.svg?branch=master)](https://travis-ci.org/tersesystems/securitybuilder)

# Security Builders

This library implements a set of "fluent" API builders for the `java.security` classes, and provides more typesafe, intuitive API to access trust stores, key stores and keys.  The primary purpose of this library is to make small tasks easy, and provide better integration with the JSSE stack.  

## Installation

### Maven

In your pom.xml:

```xml
<dependency>
    <groupId>com.tersesystems.securitybuilder</groupId>
    <artifactId>securitybuilder</artifactId>
    <version>1.0.0</version><!-- see badge for latest version -->
</dependency>
```

### sbt

```scala
libraryDependencies += "com.tersesystems.securitybuilder" % "securitybuilder" % "1.0.0"
```

## Usage

The primary use of this package is to set up test X.509 certificates, private keys and trust stores.  The [Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html) lays out how to create and initialize certificates, keystores, and so on, but typically does so in frustrating ways.  
 
The assumption is that you'll be working with Java 1.8 but with decent algorithms, so there are a number of preset defaults.  The builders are thread-safe and only build when you pull the trigger, but assume immutable input, so don't pass in arrays or lists that you are still fiddling with.

All the classes are in `com.tersesystems.securitybuilder` package.

```java
import com.tersesystems.securitybuilder.*;
```

In general, if you're just using the JCA, there are some [based off Latacora's Cryptographic Right Answers](https://latacora.singles/2018/04/03/cryptographic-right-answers.html):

* Use RSA with 2048 bit key length and SHA-2 for public and private keys.
* Use AES-GCM for encryption but **SEE WARNING BELOW**, and never reuse the IV.  There is no provable difference between AES-128 and AES-256, so [don't worry about it](http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html) and use AES-256.  
* If you're going over the network, you generally want full on TLS, so use JSSE with [debugjsse](https://github.com/tersesystems/debugjsse) as the provider to see what's going on under the hood.  Be aware that SSLEngine/SSLSocket does not know that you're using HTTPS, so you need to [define hostname verification](https://tersesystems.com/blog/2014/03/23/fixing-hostname-verification/) yourself by setting `sslParameters.setEndpointIdentificationAlgorithm("HTTPS")`. 
* Use an HMAC with at least SHA256, and a secret key that has at least 96 bits of entropy -- `EntropySource.salt()` uses 256 bits.
* Use a MessageDigest with at least SHA256.
* Use PBKDF2 with a SHA-2 HMAC [if you have to](https://pthree.org/2016/06/28/lets-talk-password-hashing/), but if you can use [jBCrypt](http://www.mindrot.org/projects/jBCrypt/) 
or [scrypt](https://github.com/wg/scrypt) go with that.
* There's no real need to use your own SecureRandom, and you don't need to use `useInstanceStrong`, the entropy pool is the same and [you may get blocking](https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/).  Use `EntropySource`.

### WARNING

Please be aware that some of the algorithms in the JCA are way, way out of date.

If you need a cryptography API, **DON'T USE THE JCA!**  Even with these builders, building your own crypto using a low level library is like [juggling chainsaws in the dark](https://www.usenix.org/sites/default/files/conference/protected-files/hotsec15_slides_green.pdf).  In particular, low level libraries don't do key management and key rotation very well.

Use [Google Tink](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md) instead, which has support for [storing keysets](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#storing-keysets), [symmetric key encryption](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#symmetric-key-encryption), [digital signatures](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#digitial-signatures), [envelope encryption](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#envelope-encryption) and [key rotation](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#key-rotation). 

Google Tink doesn't do everything: in that case, I recommend looking for a fallback professional high-level library rather than rolling your own.  This will typically involve an binding on top of a C library like [lazysodium](https://github.com/terl/lazysodium-java) on top of [libsodium](https://download.libsodium.org/doc/), or a specialized crypto framework like [Noise-Java](https://github.com/rweather/noise-java) implementing the [Noise Protocol Framework](http://noiseprotocol.org/).

## JSSE (Java TLS Classes)

### X509CertificateCreator

Creates an X509Certificate or a chain of X509Certificate.  

Very useful for building up certificates if you use `chain()`.

```java
public class X509CertificateCreatorTest {
  @Test
  public void testFunctionalStyle() throws Exception {
    FinalStage<RSAKeyPair> keyPairCreator = KeyPairCreator.creator().withRSA().withKeySize(2048);
    RSAKeyPair rootKeyPair = keyPairCreator.create();
    RSAKeyPair intermediateKeyPair = keyPairCreator.create();
    RSAKeyPair eePair = keyPairCreator.create();

    IssuerStage<RSAPrivateKey> creator =
        X509CertificateCreator.creator().withSHA256withRSA().withDuration(Duration.ofDays(365));

    String issuer = "CN=letsencrypt.derp,O=Root CA";
    X509Certificate[] chain =
        creator
            .withRootCA(issuer, rootKeyPair, 2)
            .chain(
                rootKeyPair.getPrivate(),
                rootCreator ->
                    rootCreator
                        .withPublicKey(intermediateKeyPair.getPublic())
                        .withSubject("OU=intermediate CA")
                        .withCertificateAuthorityExtensions(0)
                        .chain(
                            intermediateKeyPair.getPrivate(),
                            intCreator ->
                                intCreator
                                    .withPublicKey(eePair.getPublic())
                                    .withSubject("CN=tersesystems.com")
                                    .withEndEntityExtensions()
                                    .chain()))
            .create();

    PrivateKeyStore privateKeyStore =
        PrivateKeyStore.create("tersesystems.com", eePair.getPrivate(), chain);
    TrustStore trustStore = TrustStore.create(singletonList(chain[2]), cert -> "letsencrypt.derp");

    try {
      final PKIXCertPathValidatorResult result = CertificateChainValidator.validator()
          .withAnchor(new TrustAnchor(issuer, rootKeyPair.getPublic(), null))
          .withCertificates(chain)
          .validate();
      final PublicKey subjectPublicKey = result.getPublicKey();
      assertThat(subjectPublicKey).isEqualTo(eePair.getPublic());
    } catch (final CertPathValidatorException cpve) {
      fail("Cannot test exception", cpve);
    }

    SSLContext sslContext =
        SSLContextBuilder.builder()
            .withTLS()
            .withKeyManager(
                KeyManagerBuilder.builder()
                    .withSunX509()
                    .withPrivateKeyStore(privateKeyStore)
                    .build())
            .withTrustManager(
                TrustManagerBuilder.builder()
                    .withDefaultAlgorithm()
                    .withTrustStore(trustStore)
                    .build())
            .build();
    assertThat(sslContext).isNotNull();
  }
}
```

Admittedly this doesn't look very simple, but you should see the code it replaces.

### CertificateBuilder

Builds a `java.security.Certificate` from a source.  

If you use `withX509()`, it will give you an `X509Certificate`.

```java
public class CertificateBuilderTest {
  @Test
  public void testX509Certificate() {
    final InputStream inputStream = getClass().getResourceAsStream("/playframework.pem");
    try {
      final X509Certificate x509Certificate =
          CertificateBuilder.builder()
            .withX509()
            .withInputStream(inputStream)
            .build();
      assertThat(x509Certificate.getSigAlgName()).isEqualTo("SHA256withECDSA");
    } catch (final CertificateException e) {
      fail(e.getMessage(), e);
    }
  }
}
```

### KeyManagerBuilder

Builds a [`KeyManager`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#KeyManagerFactory) from input.  If you use `withNewSunX509()`, then you get a `X509ExtendedKeyManager` that can differentiate between RSA / DSA keys, pick out unexpired keys, and use password specific entries out of the store (if you use the keystore builder defined below).   See [Key Managers and Key Stores](https://tersesystems.com/blog/2018/09/08/keymanagers-and-keystores/) for the gory details.

Recommend using with [debugjsse](https://github.com/tersesystems/debugjsse) provider.

```java
public class KeyManagerBuilderTest {

  @Test
  public void testKeyManagerWithKeyStore() {
    try {
      final KeyStore keyStore = KeyStoreBuilder.empty();
      final X509ExtendedKeyManager keyManager =
          KeyManagerBuilder.builder()
              .withNewSunX509()
              .withKeyStore(keyStore, "".toCharArray())
              .build();
      assertThat(keyManager.getPrivateKey("derp")).isNull();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }
}
```

### TrustManagerBuilder

Builds a [`TrustManager`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#TrustManagerFactory) from input.

Recommend using with [debugjsse](https://github.com/tersesystems/debugjsse) provider.

```java
public class TrustManagerBuilderTest {
  @Test
  void builderWithKeyStore() throws Exception {
    final KeyStore keyStore = KeyStoreBuilder.empty();
    final X509ExtendedTrustManager trustManager =
        TrustManagerBuilder.builder().withDefaultAlgorithm().withKeyStore(keyStore).build();
    assertThat(trustManager.getAcceptedIssuers()).isEmpty();
  }
}
```

### SSLContextBuilder

Build a [`SSLContext`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SSLContext).  

You will typically want to combine this with `TrustManagerBuilder` and `KeyManagerBuilder`.

Recommend using with [debugjsse](https://github.com/tersesystems/debugjsse) provider.

```java
public class SSLContextBuilderTest {

  @Test
  public void testSSLContextBuilderWithTLS() {
    try {
      final SSLContext sslContext = SSLContextBuilder.builder().withTLS().build();
      sslContext.createSSLEngine();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testSSLContextBuilderWithTLSAndKeyManager() {
    try {
      final X509ExtendedKeyManager km =
          KeyManagerBuilder.builder().withNewSunX509().withDefaultKeyStoreAndPassword().build();

      final SSLContext sslContext =
          SSLContextBuilder.builder().withTLS().withKeyManager(km).build();
      sslContext.createSSLEngine();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }
}
```

### CertificateChainValidator

Validates a certificate chain using a PKIX [`CertPathValidator`](https://docs.oracle.com/javase/8/docs/api/java/security/cert/CertPathValidator.html).  See [Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html) for details, but you can safely ignore most if not all of it.

```java
public class CertificateChainValidatorTest {
  public void testCertificate(Certificate[] chain, X509Certificate rootCertificate) {
    try {
      final PKIXCertPathValidatorResult result = CertificateChainValidator.validator()
          .withTrustedCertificates(rootCertificate)
          .withCertificates(chain)
          .validate();
      final PublicKey subjectPublicKey = result.getPublicKey();
      assertThat(subjectPublicKey).isEqualTo(eePair.getPublic());
    } catch (final CertPathValidatorException cpve) {
      fail("Cannot test exception", cpve);
    }
  }
}
```

## KeyStores

Key stores are used for [key management](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement).  The `java.security.KeyStore` has three wrappers, depending on purpose: `PrivateKeyStore`, `TrustStore`, and `SecretKeyStore`.  They all extend `AbstractKeyStore`, and are written to be a drop in for `java.util.Map`.  See [blog post](https://tersesystems.com/blog/2018/07/28/building-java-keystores/) for gory details.

### PrivateKeyStore

Sets up a private keystore that is set up the way that the default SunX509 keymanager expects -- that is, all the private keys have the same password.  You work with `PrivateKeyEntry` and never have to provide the password as a parameter.

```java
public class PrivateKeyStoreTest {
  
  @Test
  public void testAdd() {
    try {
      final char[] password = "".toCharArray();
      final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(null);
      final PrivateKeyStore privateKeyStore = PrivateKeyStore.create(keyStore, password);
      final RSAKeyPair rsaKeyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).build();

      final X509Certificate rsaCertificate =
          X509CertificateCreator.builder()
              .withSHA256withRSA()
              .withNotBeforeNow()
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", rsaKeyPair, 2)
              .build();
      final PrivateKeyEntry entry =
          new PrivateKeyEntry(rsaKeyPair.getPrivate(), new Certificate[] {rsaCertificate});
      privateKeyStore.put("alias1", entry);

      // PrivateKey doesn't override equals!
      assertThat(Arrays.equals(privateKeyStore.get("alias1").getPrivateKey().getEncoded(), (entry.getPrivateKey().getEncoded()))).isTrue();
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }
}
```

### TrustStore

`TrustStore` is a wrapper around [`KeyStore`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyStore) for `TrustedCertificateEntry`.

```java
public class TrustStoreTest {
  @Test
  void testSize() {
    try {
      final KeyStore keyStore = generateStore();
      final TrustStore trustStore = TrustStore.create(keyStore);

      final RSAKeyPair rsaKeyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).build();
      final DSAKeyPair dsaKeyPair = KeyPairCreator.creator().withDSA().withKeySize(1024).build();

      final X509Certificate rsaCertificate =
          X509CertificateCreator.builder()
              .withSHA256withRSA()
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", rsaKeyPair, 2)
              .create();

      final X509Certificate dsaCertificate =
          X509CertificateCreator.builder()
              .withSignatureAlgorithm("SHA256withDSA")
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", dsaKeyPair.getKeyPair(), 2)
              .create();

      trustStore.put("rsaentry", new TrustedCertificateEntry(rsaCertificate));
      trustStore.put("dsaentry", new TrustedCertificateEntry(dsaCertificate));

      assertThat(trustStore.size()).isEqualTo(2);
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }
}
```

### SecretKeyStore

A [`KeyStore`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyStore) that contains only `SecretKeyEntry`.  

Use this with a KeyStore format of type PKCS12.

```java
public class SecretKeyStoreTest {
  @Test
  void testSize() {
    try {
      String password = "hello world".toCharArray();
      byte[] salt = EntropySource.salt();

      final Map<String, ProtectionParameter> passwordMap =
          Collections.singletonMap("username", new PasswordProtection(password));
      final SecretKeyStore secretKeyStore = generateSecretKeyStore(passwordMap);
  
      PBEKey secretKey = PasswordBuilder.builder()
        .withPBKDF2WithHmacSHA512()
        .withPassword(password)
        .withIterations(10000)
        .withSalt(salt)
        .withKeyLength(64 * 8)
        .build();
    
      secretKeyStore.put("username", new SecretKeyEntry(secretKey));
      assertThat(secretKeyStore.size()).isEqualTo(1);
    } catch (final KeyStoreException
        | IOException
        | NoSuchAlgorithmException
        | CertificateException
        | InvalidKeySpecException e) {
      fail(e);
    }
  }
}
```

### KeyStoreBuilder

Builds a [`KeyStore`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyStore).

```java
public class KeyStoreBuilderTest {

  @Test
  public void testKeyStoreBuilderWithPathAndNoPassword() {
    try {
      final Path tempPath = Files.createTempFile(null, null);
      final KeyStore keyStore = KeyStoreBuilder.empty();
      try (OutputStream outputStream = Files.newOutputStream(tempPath)) {
        keyStore.store(outputStream, "".toCharArray());
      }

      final KeyStore keyStoreFromPath =
          KeyStoreBuilder.builder().withDefaultType().withPath(tempPath).withNoPassword().build();
      assertThat(keyStoreFromPath.getType()).isEqualTo(KeyStore.getDefaultType());
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }
}
```

### KeyStoreDefaults

Allows access to the default `KeyStore` used for CA certificates and for the [private key store location](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#CustomizingStores).

### KeyManagerKeyStoreBuilder

Builds a `KeyStore.Builder`, using a keystore builder that is able to send different passwords to the "NewSunX509" keymanager.  

**The out of the box `KeyStore.Builder` API does not do this!**  See [blog post](https://tersesystems.com/blog/2018/09/08/keymanagers-and-keystores/) for details.

```java
public class DifferentPasswordsTest {

  @Test
  public void testWithBuilder() throws GeneralSecurityException, IOException {
    final char[] password1 = "password1".toCharArray();
    final char[] password2 = "password2".toCharArray();
    final Map<String, ProtectionParameter> passwordsMap = new HashMap<>();
    passwordsMap.put("rsaentry", new PasswordProtection(password1));
    passwordsMap.put("dsaentry", new PasswordProtection(password2));

    final KeyStore keyStore = generateStore();
    final KeyStore.Builder builder =
        KeyManagerKeyStoreBuilder.newInstance(keyStore, passwordsMap::get);

    final KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
    kmf.init(new KeyStoreBuilderParameters(builder));
    final X509ExtendedKeyManager keyManager = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];

    final String rsaAlias = keyManager.chooseServerAlias("RSA", null, null);
    assertThat(rsaAlias).contains("rsaentry");
    final PrivateKey rsaPrivateKey = keyManager.getPrivateKey(rsaAlias);
    assertThat(rsaPrivateKey).isNotNull(); // can get password

    final String dsaAlias = keyManager.chooseServerAlias("DSA", null, null);
    assertThat(dsaAlias).contains("dsaentry");
    final PrivateKey dsaPrivateKey = keyManager.getPrivateKey(dsaAlias);
    assertThat(dsaPrivateKey).isNotNull(); // can get password
  }
}
```

## Key Builders and Creators

### KeyPairCreator

Creates a new [`KeyPair`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyPair) containing `PublicKey` and `PrivateKey` using a [`KeyPairGenerator`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyPairGenerator). 
 
If you use `withRSA`, `withDSA` or `withEC` then you get back `RSAKeyPair` etc.

```java
class KeyPairCreatorTest {
  @Test
  void testWithAlgorithm() throws GeneralSecurityException {
    final KeyPair keyPair = KeyPairCreator.creator().withAlgorithm("RSA").withKeySize(2048).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithRSA() throws GeneralSecurityException {
    final RSAKeyPair keyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithDSA() throws GeneralSecurityException {
    final DSAKeyPair keyPair = KeyPairCreator.creator().withDSA().withKeySize(1024).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("DSA");
  }

  @Test
  void testWithDH() throws GeneralSecurityException {
    final DHKeyPair keyPair = KeyPairCreator.creator().withDH().withKeySize(1024).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("DH");
  }

  @Test
  void testWithEC() throws GeneralSecurityException {
    final ECKeyPair keyPair = KeyPairCreator.creator().withEC().withKeySize(224).create();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("EC");
  }
}
```

### EncodedKeySpecBuilder

Builds a [`EncodedKeySpec`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#PKCS8EncodedKeySpec) from existing source material.
 
You can use either `PKCS8EncodedKeySpec`, commonly used for PEM encoded private keys, or `X509EncodedKeySpec`, used for PEM encoded X.509 certificates.

```java
class PKCS8EncodedKeySpecBuilderTest {
  @Test
  public void testGeneration() throws Exception {
    // Read a private key
    final Reader reader = new InputStreamReader(getClass().getResourceAsStream("/private-key.pem"));
    final PKCS8EncodedKeySpec keySpec =
        PKCS8EncodedKeySpecBuilder.builder().withReader(reader).withNoPassword().build();
    assertThat(keySpec.getFormat()).isEqualTo("PKCS#8");
  }
}
```

### PublicKeyBuilder

Builds a [`PublicKey`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Key). 
 
Will provide public key of the appropriate type using `withRSA`, `withDSA`, or `withEC` methods.

```java
public class PublicKeyBuilderTest {

  @Test
  public void testRSAPublicKey() throws GeneralSecurityException {
    final BigInteger modulus =
        new BigInteger(
            "b4a7e46170574f16a97082b22be58b6a2a629798419"
                + "be12872a4bdba626cfae9900f76abfb12139dce5de5"
                + "6564fab2b6543165a040c606887420e33d91ed7ed7",
            16);
    final BigInteger exp = new BigInteger("11", 16);
    final RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exp);
    RSAPublicKey rsaPublicKey =
        PublicKeyBuilder.builder().withRSA().withKeySpec(rsaPublicKeySpec).build();
    assertThat(rsaPublicKey).isNotNull();
  }
}
```

### PrivateKeyBuilder

Builds a [`PrivateKey`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Key).  

Will provide private key of the appropriate type using `withRSA`, `withDSA`, or `withEC` methods.

```java
class PrivateKeyBuilderTest {

  @Test
  void builderWithRSA() throws GeneralSecurityException {
    final RSAPrivateKey exampleKey =
        (RSAPrivateKey)
            KeyPairCreator.creator().withAlgorithm("RSA").withKeySize(2048).build().getPrivate();
    final RSAPrivateKeySpec rsaPrivateKeySpec =
        new RSAPrivateKeySpec(exampleKey.getModulus(), exampleKey.getPrivateExponent());
    final RSAPrivateKey privateKey =
        PrivateKeyBuilder.builder().withRSA().withKeySpec(rsaPrivateKeySpec).build();

    assertThat(privateKey).isNotNull();
  }
}
```

### SecretKeyBuilder

Builds a [`SecretKey`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SecretKey).

The algorithms are in <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider">The SunJCE Provider</a>.

```java
public class SecretKeyBuilderTest {
  @Test
  public void testSecretKeySpec() throws Exception {
    byte[] aesKeyData = "abc123".getBytes();

    SecretKey secretKey = SecretKeyBuilder.builder()
        .withSecretKeySpec("AES")
        .withData(aesKeyData)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }
}
```

## MACs, Signatures, Passwords

### MacBuilder

Builds an Message Authentication Code based on cryptographic hashing, aka [`Mac`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac).

```java
public class MacBuilderTest {
  @Test
  void testMacBuild() throws GeneralSecurityException {
    SecretKey key = new SecretKeySpec("privatekey".getBytes(), "HmacSHA256");

    Mac sha256Mac = MacBuilder.builder().withAlgorithm("HmacSHA256").withKey(key).build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));

    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output).isEqualTo("27f0d5331806fb9f21247b19bee883a7cfe54c069d6e28edccc2cff8e78c4a74");
  }

  @Test
  void testSecretKeySpec() throws GeneralSecurityException {
    Mac sha256Mac = MacBuilder.builder().withSecretKeySpec("HmacSHA256").withString("privatekey").build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));

    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output).isEqualTo("27f0d5331806fb9f21247b19bee883a7cfe54c069d6e28edccc2cff8e78c4a74");
  }

  @Test
  void testHmac() throws GeneralSecurityException {
    Mac sha256Mac = MacBuilder.builder().withHmacSHA256().withString("privatekey").build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));

    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output).isEqualTo("27f0d5331806fb9f21247b19bee883a7cfe54c069d6e28edccc2cff8e78c4a74");
  }
}
```

### MessageDigestBuilder

Builds a [`MessageDigest`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#MessageDigest).

These are intentionally curtailed so you don't pick out weak MessageDigest algorithms.

```java
public class MessageDigestBuilderTest {
  @Test
  public void testSha512() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.sha512().getAlgorithm()).isEqualTo("SHA-512");
  }
}
```

### SignatureBuilder

Builds a [`Signature`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#Signature). for either signing or verifying. 

```java
public class SignatureBuilderTest {

  @Test
  public void testSignature() {
    try {
      final KeyPair<?, ?> keyPair =
          KeyPairCreator.creator().withAlgorithm("RSA").withKeySize(2048).build();
      final PrivateKey privateKey = keyPair.getPrivate();
      final PublicKey publicKey = keyPair.getPublic();

      final Signature signingSignature =
          SignatureBuilder.builder().withAlgorithm("SHA256withRSA").signing(privateKey).build();
      final byte[] digest = signingSignature.sign();

      final Signature verifySignature =
          SignatureBuilder.builder().withAlgorithm("SHA256withRSA").verifying(publicKey).build();
      assertThat(verifySignature.verify(digest)).isEqualTo(true);
    } catch (final Exception e) {
      Fail.fail(e.getMessage(), e);
    }
  }
}
```

### EntropySource

Pulls from SecureRandom `/dev/urandom`, using the recommended number of random bits.  See [blog post](https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/) for details.

```java
public class EntropySource {
  /**
   * Provides an initialization vector for GCM.
   */
  public static byte[] gcmIV() {
    return nextBytes(DEFAULT_GCM_IV_LENGTH);
  }

  /**
   * Provides a salt, which must be unique but is not private.
   */
  public static byte[] salt() {
    return nextBytes(DEFAULT_SALT_LENGTH);
  }
}
```

## Odds and Ends

Finally, there's some code which is useful in a pinch but which doesn't really go anywhere else.  

### AuthenticatedEncryptionBuilder

Makes generating an AES-GCM cipher a bit easier.  You [always](https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/) want to use an authenticated encryption mode.

Again, you're better off using Google Tink's [symmetric encryption](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#symmetric-key-encryption) if you're doing encryption -- and if you're going over the network, you generally want full on TLS.  See the usage and warnings up top.

```java
public class AuthenticatedEncryptionBuilderTest {
  @Test
  public void testCipher() throws GeneralSecurityException {
    final SecretKey aesSecretKey = SecretKeyGenerator.generate().withAES().withKeySize(128).build();
    final SecretKeySpec secretKeySpec = new SecretKeySpec(aesSecretKey.getEncoded(), aesSecretKey.getAlgorithm());
    final IvStage builder = AuthenticatedEncryptionBuilder.builder().withSecretKey(secretKeySpec);

    byte[] gcmIV = EntropySource.gcmIV();
    byte[] inputData = "input text".getBytes(UTF_8);

    byte[] encryptedData = builder.withIv(gcmIV).encrypt().doFinal(inputData);
    byte[] decryptedData = builder.withIv(gcmIV).decrypt().doFinal(encryptedData);

    String decryptString = new String(decryptedData, UTF_8);
    assertThat(decryptString).isEqualTo("input text");
  }
}
```

### PasswordBuilder

A specialized secret key builder for encrypting passwords.  

Use PBKDF2 with a SHA-2 HMAC [if you have to](https://pthree.org/2016/06/28/lets-talk-password-hashing/), but if you can use [jBCrypt](http://www.mindrot.org/projects/jBCrypt/) or [scrypt](https://github.com/wg/scrypt), go with that.

```java
public class PasswordBuilderTest {

  @Test
  public void testPasswordSpec() throws Exception {
    byte[] salt = EntropySource.salt();

    PBEKey passwordBasedEncryptionKey = PasswordBuilder.builder()
        .withPBKDF2WithHmacSHA512()
        .withPassword("hello world".toCharArray())
        .withIterations(1000)
        .withSalt(salt)
        .withKeyLength(64 * 8)
        .build();

    byte[] encryptedPassword = passwordBasedEncryptionKey.getEncoded();
    assertThat(passwordBasedEncryptionKey.getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA512");
  }
}
```

### KeyAgreementBuilder

Creates a [KeyAgreement](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyAgreement) instance.

This is typically used with Diffie-Hellman, most commonly found in SSH.  Use [jsch](http://www.jcraft.com/jsch/) if you want SSH, otherwise you're better off using a high level crypto library like those described in the WARNING section up top.

The [canonical DH key exchange](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#DH2Ex):

```java
public class KeyAgreementBuilderTest {
  @Test
  public void testKeyAgreementParams() throws GeneralSecurityException, IOException {
    // Alice creates her own DH key pair with 2048-bit key size
    DHKeyPair aliceKpair = KeyPairCreator.creator().withDH().withKeySize(2048).create();

    // Alice creates and initializes her DH KeyAgreement object
    KeyAgreement aliceKeyAgree = KeyAgreementBuilder.builder()
        .withDH()
        .withKey(aliceKpair.getPrivate())
        .build();

    // Alice encodes her public key, and sends it over to Bob.
    byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

    //* Let's turn over to Bob. Bob has received Alice's public key
    //* in encoded format.
    //* He instantiates a DH public key from the encoded key material.
    DHPublicKey alicePubKey = PublicKeyBuilder.builder().withDH()
        .withKeySpec(new X509EncodedKeySpec(alicePubKeyEnc)).build();

    //* Bob gets the DH parameters associated with Alice's public key.
    //* He must use the same parameters when he generates his own key
    //* pair.
    DHParameterSpec dhParamFromAlicePubKey = alicePubKey.getParams();

    // Bob creates his own DH key pair
    DHKeyPair bobKpair = KeyPairCreator.creator().withDH().withKeySpec(dhParamFromAlicePubKey)
        .create();

    // Bob creates and initializes his DH KeyAgreement object
    KeyAgreement bobKeyAgree = KeyAgreementBuilder.builder().withDH().withKey(bobKpair.getPrivate())
        .build();

    // Bob encodes his public key, and sends it over to Alice.
    byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

    //* Alice uses Bob's public key for the first (and only) phase
    //* of her version of the DH protocol.
    //* Before she can do so, she has to instantiate a DH public key
    //* from Bob's encoded key material.
    DHPublicKey bobPubKey = PublicKeyBuilder.builder().withDH()
        .withKeySpec(new X509EncodedKeySpec(bobPubKeyEnc)).build();
    aliceKeyAgree.doPhase(bobPubKey, true);

    //* Bob uses Alice's public key for the first (and only) phase
    //* of his version of the DH protocol.
    bobKeyAgree.doPhase(alicePubKey, true);

    // At this stage, both Alice and Bob have completed the DH key
    // agreement protocol. Both generate the (same) shared secret.
    byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
    byte[] bobSharedSecret = new byte[aliceSharedSecret.length];
    bobKeyAgree.generateSecret(bobSharedSecret, 0);
    assertThat(Arrays.equals(aliceSharedSecret, bobSharedSecret)).isTrue();

    // Now let's create a SecretKey object using the shared secret
    // and use it for encryption.
    SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
    SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");

    // Bob encrypts, using AES in GCM mode
    final byte[] iv = EntropySource.gcmIV();
    Cipher bobCipher = AuthenticatedEncryptionBuilder.builder().withSecretKey(bobAesKey).withIv(iv)
        .encrypt();
    byte[] cleartext = "This is just an example".getBytes();
    byte[] ciphertext = bobCipher.doFinal(cleartext);

    // Alice decrypts, using AES in GCM mode
    Cipher aliceCipher = AuthenticatedEncryptionBuilder.builder().withSecretKey(aliceAesKey).withIv(iv).decrypt();
    byte[] recovered = aliceCipher.doFinal(ciphertext);
    assertThat(Arrays.equals(cleartext, recovered)).isTrue();
  }
}
```
