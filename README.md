# Security Builders

The [Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html) lays out how to create and initialize certificates, keystores, and so on, but typically does so in frustrating ways.  

This library implements a set of "fluent" API builders for the `java.security` classes, and provides more typesafe, intuitive API to access trust stores, key stores and keys.  The primary purpose of this library is to make small tasks easy, and provide better integration with the JSSE stack.

## WARNING

If you need a cryptography API, **DON'T USE THE JCA!**  Even with these builders, building your own crypto using a low level library is like [juggling chainsaws in the dark](https://www.usenix.org/sites/default/files/conference/protected-files/hotsec15_slides_green.pdf).  

Use [Google Tink](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md) instead, which has support for [storing keysets](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#storing-keysets), [symmetric key encryption](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#symmetric-key-encryption), [digital signatures](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#digitial-signatures), [envelope encryption](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#envelope-encryption) and [key rotation](https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#key-rotation). 

## Installation

### Maven

From Bintray:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<settings xsi:schemaLocation='http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd'
          xmlns='http://maven.apache.org/SETTINGS/1.0.0' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
    
    <profiles>
        <profile>
            <repositories>
                <repository>
                    <snapshots>
                        <enabled>false</enabled>
                    </snapshots>
                    <id>bintray-tersesystems-maven</id>
                    <name>bintray</name>
                    <url>https://dl.bintray.com/tersesystems/maven</url>
                </repository>
            </repositories>
            <pluginRepositories>
                <pluginRepository>
                    <snapshots>
                        <enabled>false</enabled>
                    </snapshots>
                    <id>bintray-tersesystems-maven</id>
                    <name>bintray-plugins</name>
                    <url>https://dl.bintray.com/tersesystems/maven</url>
                </pluginRepository>
            </pluginRepositories>
            <id>bintray</id>
        </profile>
    </profiles>
    <activeProfiles>
        <activeProfile>bintray</activeProfile>
    </activeProfiles>
</settings>
```

In your pom.xml:

```xml
<repositories>
  <repository>
    <id>central</id>
    <name>bintray</name>
    <url>http://jcenter.bintray.com</url>
  </repository>
</repositories>

<dependency>
    <groupId>com.tersesystems.securitybuilder</groupId>
    <artifactId>securitybuilder</artifactId>
    <version>0.1.0</version><!-- see badge for latest version -->
</dependency>
```

### sbt

```scala
resolvers += Resolver.jcenterRepo 
libraryDependencies += "com.tersesystems.securitybuilder" % "securitybuilder" % "0.1.0"
```

## Usage

### KeyManagerBuilder

Builds a [`KeyManager`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#KeyManagerFactory) from input.  If you use `withNewSunX509()`, then you get a `X509ExtendedKeyManager` that is the default.

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

### KeyPairBuilder

Builds a [`KeyPair`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyPair) using a [`KeyPairGenerator`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyPairGenerator). 
 
If you use `withRSA`, `withDSA` or `withEC` then you get back `RSAKeyPair` etc.

```java
class KeyPairBuilderTest {
  @Test
  void testWithAlgorithm() throws GeneralSecurityException {
    final KeyPair keyPair = KeyPairBuilder.builder().withAlgorithm("RSA").withKeySize(2048).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithRSA() throws GeneralSecurityException {
    final RSAKeyPair keyPair = KeyPairBuilder.builder().withRSA().withKeySize(2048).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("RSA");
  }

  @Test
  void testWithDSA() throws GeneralSecurityException {
    final DSAKeyPair keyPair = KeyPairBuilder.builder().withDSA().withKeySize(1024).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("DSA");
  }

  @Test
  void testWithEC() throws GeneralSecurityException {
    final ECKeyPair keyPair = KeyPairBuilder.builder().withEC().withKeySize(224).build();
    Assertions.assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("EC");
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

### PKCS8EncodedKeySpecBuilder

Builds a [`PKCS8EncodedKeySpec`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#PKCS8EncodedKeySpec), commonly used for PEM encoded private keys.

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

### PrivateKeyBuilder

Builds a [`PrivateKey`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyFactory).  

Will provide private key of the appropriate type using `withRSA`, `withDSA`, or `withEC` methods.

```java
class PrivateKeyBuilderTest {

  @Test
  void builderWithRSA() throws GeneralSecurityException {
    final RSAPrivateKey exampleKey =
        (RSAPrivateKey)
            KeyPairBuilder.builder().withAlgorithm("RSA").withKeySize(2048).build().getPrivate();
    final RSAPrivateKeySpec rsaPrivateKeySpec =
        new RSAPrivateKeySpec(exampleKey.getModulus(), exampleKey.getPrivateExponent());
    final RSAPrivateKey privateKey =
        PrivateKeyBuilder.builder().withRSA().withKeySpec(rsaPrivateKeySpec).build();

    assertThat(privateKey).isNotNull();
  }
}
```

### PublicKeyBuilder

Builds a [`PublicKey`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyFactory). 
 
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

### SecretKeyBuilder

Builds a [`SecretKey`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SecretKeyFactory)

The SecretKeyFactory algorithms are in <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider">The SunJCE Provider</a>

Uses an algorithm for SecretKeySpec.  These are based off the Cipher algorithm name, and most of them are in <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#OracleUcrypto">The OracleUcrypto Provider</a>, i.e. "AES".

```java
public class SecretKeyBuilderTest {
  @Test
  public void testAlgorithm() throws Exception {
    String password = "changeit";
    String salt = "abc123";
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
    SecretKey secretKey = SecretKeyBuilder.builder()
        .withAlgorithm("PBKDF2WithHmacSHA1")
        .withKeySpec(keySpec)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA1");
  }

  @Test
  public void testSecretKeySpec() throws Exception {
    byte[] aesKeyData = getKeyData();

    SecretKey secretKey = SecretKeyBuilder.builder()
        .withSecretKeySpec("AES")
        .withData(aesKeyData)
        .build();

    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
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
          KeyPairBuilder.builder().withAlgorithm("RSA").withKeySize(2048).build();
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

### X509CertificateBuilder

Creates an X509Certificate or a chain of X509Certificate.  

Very useful for building up certificates if you use `chain()`.

```java
public class X509CertificateBuilderTest {

  @Test
  public void testFunctionalStyle() throws Exception {

    BuildFinal<RSAKeyPair> keyPairBuilder = KeyPairBuilder.builder().withRSA().withKeySize(2048);
    final RSAKeyPair rootKeyPair = keyPairBuilder.build();
    final RSAKeyPair intermediateKeyPair = keyPairBuilder.build();
    final RSAKeyPair eePair = keyPairBuilder.build();

    IssuerStage<RSAPrivateKey> builder =
        X509CertificateBuilder.builder().withSHA256withRSA().withDuration(Duration.ofDays(365));

    String issuer = "CN=letsencrypt.derp,O=Root CA";
    X509Certificate[] chain =
        builder
            .withRootCA(issuer, rootKeyPair, 2)
            .chain(
                rootKeyPair.getPrivate(),
                rootBuilder ->
                    rootBuilder
                        .withPublicKey(intermediateKeyPair.getPublic())
                        .withSubject("OU=intermediate CA")
                        .withCertificateAuthorityExtensions(0)
                        .chain(
                            intermediateKeyPair.getPrivate(),
                            intBuilder ->
                                intBuilder
                                    .withPublicKey(eePair.getPublic())
                                    .withSubject("CN=tersesystems.com")
                                    .withEndEntityExtensions()
                                    .chain()))
            .build();

    PrivateKeyStore privateKeyStore =
        PrivateKeyStore.create("tersesystems.com", eePair.getPrivate(), chain);
    TrustStore trustStore = TrustStore.create(singletonList(chain[2]), cert -> "letsencrypt.derp");

    SSLContext sslContext = ...
    assertThat(sslContext).isNotNull();
  }
}
```

### KeyStores

The `java.security.KeyStore` has three wrappers, depending on purpose: `PrivateKeyStore`, `TrustStore`, and `SecretKeyStore`.  They all extend `AbstractKeyStore`, and are written to be a drop in for `java.util.Map`.  See [blog post](https://tersesystems.com/blog/2018/07/28/building-java-keystores/) for gory details.

#### PrivateKeyStore

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
      final RSAKeyPair rsaKeyPair = KeyPairBuilder.builder().withRSA().withKeySize(2048).build();

      final X509Certificate rsaCertificate =
          X509CertificateBuilder.builder()
              .withSHA256withRSA()
              .withNotBeforeNow()
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", rsaKeyPair, 2)
              .build();
      final PrivateKeyEntry entry =
          new PrivateKeyEntry(rsaKeyPair.getPrivate(), new Certificate[] {rsaCertificate});
      privateKeyStore.put("alias1", entry);

      // PrivateKey doesn't override equals!
      assertThat(privateKeyStore.get("alias1")).isEqualToComparingFieldByField(entry);
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }
}
```

#### TrustStore

`TrustStore` is a wrapper around `KeyStore` for `TrustedCertificateEntry`.

```java
public class TrustStoreTest {
  @Test
  void testSize() {
    try {
      final KeyStore keyStore = generateStore();
      final TrustStore trustStore = TrustStore.create(keyStore);

      final RSAKeyPair rsaKeyPair = KeyPairBuilder.builder().withRSA().withKeySize(2048).build();
      final DSAKeyPair dsaKeyPair = KeyPairBuilder.builder().withDSA().withKeySize(1024).build();

      final X509Certificate rsaCertificate =
          X509CertificateBuilder.builder()
              .withSHA256withRSA()
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", rsaKeyPair, 2)
              .build();

      final X509Certificate dsaCertificate =
          X509CertificateBuilder.builder()
              .withSignatureAlgorithm("SHA256withDSA")
              .withDuration(Duration.ofDays(365))
              .withRootCA("CN=example.com", dsaKeyPair.getKeyPair(), 2)
              .build();

      trustStore.put("rsaentry", new TrustedCertificateEntry(rsaCertificate));
      trustStore.put("dsaentry", new TrustedCertificateEntry(dsaCertificate));

      assertThat(trustStore.size()).isEqualTo(2);
    } catch (final Exception e) {
      fail(e.getMessage());
    }
  }
}
```

#### SecretKeyStore

A `KeyStore` that contains only `SecretKeyEntry`.  

Use this with a KeyStore format of type PKCS12 or JCEKS.

```java
public class SecretKeyStoreTest {
  @Test
  void testSize() {
    try {
      final String password = "test";
      final Map<String, ProtectionParameter> passwordMap =
          Collections.singletonMap("alias", new PasswordProtection(password.toCharArray()));
      final SecretKeyStore secretKeyStore = generateSecretKeyStore(passwordMap);
  
      final int pswdIterations = 65536;
      final int keySize = 256;
      final byte[] saltBytes = {0, 1, 2, 3, 4, 5, 6};
  
      final PBEKeySpec spec =
          new PBEKeySpec(password.toCharArray(), saltBytes, pswdIterations, keySize);
      final SecretKey secretKey = SecretKeyBuilder.withAlgorithm("PBKDF2WithHmacSHA1").withKeySpec(spec).build();
      secretKeyStore.put("alias", new SecretKeyEntry(secretKey));
  
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

## Building

```bash
mvn clean compile test package
```

## Releasing

Uses [Maven Release Plugin](http://maven.apache.org/maven-release/maven-release-plugin/plugin-info.html):

```
mvn release:prepare
mvn release:perform
```