package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DomainLoadStoreParameter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;

public class DomainKeyStoreTest {

  @Test
  public void testMe() throws GeneralSecurityException, IOException {
    final KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
    kmf.init(generateStore(), null);
    final X509ExtendedKeyManager keyManager = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];

    final X500Principal name = new X500Principal("CN=example.com");
    final String[] aliases = keyManager.getServerAliases("RSA", new Principal[] {name});
    final String alias = aliases[0];
    final PrivateKey privateKey = keyManager.getPrivateKey(alias);
    assertThat(privateKey).isNotNull();
  }

  public static ProtectionParameter createPKCS11Password(final char[] password) {
    return new KeyStore.CallbackHandlerProtection(
        callbacks ->
            Arrays.stream(callbacks)
                .map(callback -> (PasswordCallback) callback)
                .forEach(pc -> pc.setPassword(password)));
  }

  private KeyStore generateStore() throws GeneralSecurityException, IOException {
    final RSAKeyPair keyPair = KeyPairCreator.creator().withRSA().withKeySize(2048).build();

    final X509Certificate certificate =
        X509CertificateCreator.creator()
            .withSHA256withRSA()
            .withDuration(Duration.ofDays(365))
            .withRootCA("CN=example.com", keyPair, 2)
            .build();

    final Path privateKeyStorePath = Files.createTempFile(null, ".p12");
    final KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
    pkcs12.load(null);

    final char[] privateKeyPassword = "".toCharArray();
    pkcs12.setKeyEntry(
        "example.com", keyPair.getPrivate(), privateKeyPassword, new Certificate[] {certificate});
    try (OutputStream outputStream = Files.newOutputStream(privateKeyStorePath)) {
      pkcs12.store(outputStream, privateKeyPassword);
    }

    final List<String> lines = new ArrayList<>();
    lines.add("domain app1 {");
    lines.add("\tkeystore app1keystore");
    lines.add(String.format("\t\tkeystoreURI=\"%s\";", privateKeyStorePath.toUri()));
    lines.add("");
    lines.add("\tkeystore systemtruststore");
    lines.add("\t\tkeystoreURI=\"${java.home}/lib/security/cacerts\";");
    lines.add("};");

    final Path tempFile = Files.createTempFile(null, null);
    Files.write(tempFile, lines, StandardCharsets.UTF_8);

    final URI uri = tempFile.toUri();
    final Map<String, ProtectionParameter> passwords = new HashMap<>();
    passwords.put("app1keystore", new PasswordProtection(privateKeyPassword));
    passwords.put("pkcs11keystore", createPKCS11Password("password".toCharArray()));

    final KeyStore store = KeyStore.getInstance("DKS");
    store.load(new DomainLoadStoreParameter(uri, passwords));
    return store;
  }
}
