package com.tersesystems.securitybuilder;

import static org.assertj.core.api.Assertions.*;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class KeyStoreBuilderTest {

  @Test
  public void testEmptyKeyStoreBuilder() {
    try {
      final KeyStore keyStore = KeyStoreBuilder.empty();
      assertThat(keyStore.getType()).isEqualTo(KeyStore.getDefaultType());
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testKeyStoreBuilderWithPathAndNoPassword() {
    try {
      final Path tempPath = Files.createTempFile(null, null);
      final KeyStore keyStore = KeyStoreBuilder.empty();
      keyStore.store(new FileOutputStream(tempPath.toFile()), "".toCharArray());

      final KeyStore keyStoreFromPath =
          KeyStoreBuilder.builder().withDefaultType().withPath(tempPath).withNoPassword().build();
      assertThat(keyStoreFromPath.getType()).isEqualTo(KeyStore.getDefaultType());
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testKeyStoreBuilderWithPassword() {
    try {
      final char[] password = "changeit".toCharArray();
      final Path tempPath = Files.createTempFile(null, null);
      final KeyStore keyStore = KeyStoreBuilder.empty();
      keyStore.store(new FileOutputStream(tempPath.toFile()), password);

      final KeyStore keyStoreFromPath =
          KeyStoreBuilder.builder()
              .withDefaultType()
              .withPath(tempPath)
              .withPassword(password)
              .build();
      assertThat(keyStoreFromPath.getType()).isEqualTo(KeyStore.getDefaultType());
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }

  @Test
  public void testKeyStoreBuilderWithInputStream() {
    try {
      final char[] password = "changeit".toCharArray();
      final Path tempPath = Files.createTempFile(null, null);
      final KeyStore keyStore = KeyStoreBuilder.empty();
      keyStore.store(new FileOutputStream(tempPath.toFile()), password);

      try (InputStream inputStream = Files.newInputStream(tempPath)) {
        final KeyStore keyStoreFromPath =
            KeyStoreBuilder.builder()
                .withDefaultType()
                .withInputStream(inputStream)
                .withPassword(password)
                .build();
        assertThat(keyStoreFromPath.getType()).isEqualTo(KeyStore.getDefaultType());
      }
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }

  // https://github.com/JetBrains/jdk8u_jdk/blob/master/test/sun/security/provider/KeyStore/DKSTest.java
  @Test
  public void testKeyStoreBuilderWithDomainStoreParameters() {
    if (System.getProperty("java.home") == null) {
      System.setProperty("java.home", System.getenv("JAVA_HOME") + "/jre");
    }
    try {
      final InputStream domainInput = getClass().getResourceAsStream("/domains.cfg");
      final Path tempPath = Files.createTempFile(null, null);
      java.nio.file.Files.copy(domainInput, tempPath, StandardCopyOption.REPLACE_EXISTING);

      final Map<String, KeyStore.ProtectionParameter> passwordMap = new HashMap<>();
      final KeyStore keyStoreFromPath =
          KeyStoreBuilder.builder()
              .withDomainType()
              .withURIAndPasswordMap(tempPath.toUri().resolve("#system"), passwordMap)
              .build();
      assertThat(keyStoreFromPath.getType()).isEqualTo("DKS");
    } catch (final Exception e) {
      fail(e.getMessage(), e);
    }
  }
}
