package com.tersesystems.securitybuilder;

import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public abstract class AbstractKeyStore<T extends KeyStore.Entry> implements Map<String, T> {

  @NotNull protected final Builder builder;

  protected AbstractKeyStore(@NotNull final KeyStore.Builder builder) {
    this.builder = builder;
  }

  @NotNull
  public KeyStore getKeyStore() {
    try {
      return this.builder.getKeyStore();
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  public ProtectionParameter protectionParameter(@NotNull final String alias) {
    try {
      return builder.getProtectionParameter(alias);
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  @Override
  public int size() {
    try {
      return getKeyStore().size();
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  @Override
  public boolean isEmpty() {
    try {
      return getKeyStore().size() == 0;
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  @Override
  public boolean containsKey(final Object key) {
    if (key instanceof String) {
      final String alias = (String) key;
      try {
        return getKeyStore().containsAlias(alias);
      } catch (@NotNull final KeyStoreException e) {
        throw new RuntimeKeyStoreException(e);
      }
    } else {
      return false;
    }
  }

  @SuppressWarnings("unchecked")
  @Override
  public boolean containsValue(final Object value) {
    // XXX unchecked cast
    // FIXME test for value equality, I think this only does instance equality
    final T entry = (T) value;
    return values().stream().anyMatch(thisEntry -> thisEntry.equals(entry));
  }

  @Nullable
  @SuppressWarnings("unchecked")
  @Override
  public T get(final Object key) {
    if (key instanceof String) {
      final String alias = (String) key;
      try {
        return (T) getKeyStore().getEntry(alias, protectionParameter(alias));
      } catch (@NotNull
          final NoSuchAlgorithmException
          | UnrecoverableEntryException
          | KeyStoreException e) {
        throw new RuntimeKeyStoreException(e);
      }
    }
    return null;
  }

  @Override
  public T put(final String alias, final T value) {
    try {
      ProtectionParameter protectionParameter = protectionParameter(alias);
      if (protectionParameter == null) {
        throw new IllegalStateException(
            String.format("Null protection parameter found with alias %s", alias));
      }
      getKeyStore().setEntry(alias, value, protectionParameter);
      return value;
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  @Nullable
  @SuppressWarnings("unchecked")
  @Override
  public T remove(final Object key) {
    if (key instanceof String) {
      final String alias = (String) key;
      if (containsKey(key)) {
        try {
          final T entry = (T) getKeyStore().getEntry(alias, protectionParameter(alias));
          getKeyStore().deleteEntry(alias);
          return entry;
        } catch (@NotNull
            final KeyStoreException
            | UnrecoverableEntryException
            | NoSuchAlgorithmException e) {
          throw new RuntimeKeyStoreException(e);
        }
      }
    }
    return null;
  }

  @Override
  public void putAll(@NotNull final Map<? extends String, ? extends T> map) {
    map.forEach(
        (alias, privateKey) -> {
          try {
            getKeyStore().setEntry(alias, privateKey, protectionParameter(alias));
          } catch (@NotNull final KeyStoreException e) {
            throw new RuntimeKeyStoreException(e);
          }
        });
  }

  @Override
  public void clear() {
    keySet().forEach(this::remove);
  }

  @NotNull
  @Override
  public Set<String> keySet() {
    try {
      return new HashSet<>(Collections.list(getKeyStore().aliases()));
    } catch (@NotNull final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  @NotNull
  @Override
  public Collection<T> values() {
    return keySet().stream().map(this::get).collect(Collectors.toList());
  }

  @SuppressWarnings("unchecked")
  @NotNull
  @Override
  public Set<Entry<String, T>> entrySet() {
    return keySet()
        .stream()
        .map(
            alias -> {
              try {
                T privateKeyEntry = (T) getKeyStore().getEntry(alias, protectionParameter(alias));
                return new MyEntry(alias, privateKeyEntry);
              } catch (@NotNull
                  NoSuchAlgorithmException
                  | UnrecoverableEntryException
                  | KeyStoreException e) {
                throw new RuntimeKeyStoreException(e);
              }
            })
        .collect(Collectors.toSet());
  }

  class MyEntry implements Entry<String, T> {
    @NotNull private final String alias;
    @NotNull private final T keyEntry;

    MyEntry(@NotNull final String alias, @NotNull final T keyEntry) {
      this.alias = alias;
      this.keyEntry = keyEntry;
    }

    @NotNull
    @Override
    public String getKey() {
      return alias;
    }

    @NotNull
    @Override
    public T getValue() {
      return keyEntry;
    }

    @NotNull
    @Override
    public T setValue(@NotNull final T value) {
      try {
        getKeyStore().setEntry(alias, value, protectionParameter(alias));
      } catch (@NotNull final KeyStoreException e) {
        throw new RuntimeKeyStoreException(e);
      }
      return value;
    }

    @SuppressWarnings("unchecked")
    @Contract(value = "null -> false", pure = true)
    @Override
    public boolean equals(final Object obj) {
      if (obj == this) {
        return true;
      }

      if (obj instanceof AbstractKeyStore<?>.MyEntry) {
        final MyEntry o = (MyEntry) obj;
        return o.keyEntry.equals(this.keyEntry) && o.alias.equals(this.alias);
      } else {
        return false;
      }
    }

    @Override
    public int hashCode() {
      return Objects.hash(alias, keyEntry);
    }
  }
}
