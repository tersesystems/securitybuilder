package com.tersesystems.securitybuilder;

import java.security.*;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.*;
import java.util.stream.Collectors;

public abstract class AbstractKeyStore<T extends KeyStore.Entry> implements Map<String, T> {

  protected final Builder builder;

  protected AbstractKeyStore(final KeyStore.Builder builder) {
    this.builder = builder;
  }

  public KeyStore getKeyStore() {
    try {
      return this.builder.getKeyStore();
    } catch (final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  public ProtectionParameter protectionParameter(final String alias) {
    try {
      return builder.getProtectionParameter(alias);
    } catch (final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }

  @Override
  public int size() {
    try {
      return getKeyStore().size();
    } catch (final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }


  @Override
  public boolean isEmpty() {
    try {
      return getKeyStore().size() == 0;
    } catch (final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }


  @Override
  public boolean containsKey(final Object key) {
    if (key instanceof String) {
      final String alias = (String) key;
      try {
        return getKeyStore().containsAlias(alias);
      } catch (final KeyStoreException e) {
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


  @SuppressWarnings("unchecked")
  @Override
  public T get(final Object key) {
    if (key instanceof String) {
      final String alias = (String) key;
      Objects.requireNonNull(alias, "Null alias!");
      try {
        return (T) getKeyStore().getEntry(alias, protectionParameter(alias));
      } catch (
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
      Objects.requireNonNull(alias, "Null alias!");

      ProtectionParameter protectionParameter = protectionParameter(alias);
      if (protectionParameter == null) {
        throw new IllegalStateException(
            String.format("Null protection parameter found with alias %s", alias));
      }
      getKeyStore().setEntry(alias, value, protectionParameter);
      return value;
    } catch (final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }


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
        } catch (
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
  public void putAll(final Map<? extends String, ? extends T> map) {
    map.forEach(
        (alias, privateKey) -> {
          try {
            getKeyStore().setEntry(alias, privateKey, protectionParameter(alias));
          } catch (final KeyStoreException e) {
            throw new RuntimeKeyStoreException(e);
          }
        });
  }

  @Override
  public void clear() {
    keySet().forEach(this::remove);
  }


  @Override
  public Set<String> keySet() {
    try {
      return new HashSet<>(Collections.list(getKeyStore().aliases()));
    } catch (final KeyStoreException e) {
      throw new RuntimeKeyStoreException(e);
    }
  }


  @Override
  public Collection<T> values() {
    return keySet().stream().map(this::get).collect(Collectors.toList());
  }

  @SuppressWarnings("unchecked")

  @Override
  public Set<Entry<String, T>> entrySet() {
    return keySet()
        .stream()
        .map(
            alias -> {
              try {
                T privateKeyEntry = (T) getKeyStore().getEntry(alias, protectionParameter(alias));
                return new MyEntry(alias, privateKeyEntry);
              } catch (
                  NoSuchAlgorithmException
                      | UnrecoverableEntryException
                      | KeyStoreException e) {
                throw new RuntimeKeyStoreException(e);
              }
            })
        .collect(Collectors.toSet());
  }

  class MyEntry implements Entry<String, T> {

    private final String alias;
    private final T keyEntry;

    MyEntry(final String alias, final T keyEntry) {
      this.alias = alias;
      this.keyEntry = keyEntry;
    }


    @Override
    public String getKey() {
      return alias;
    }


    @Override
    public T getValue() {
      return keyEntry;
    }


    @Override
    public T setValue(final T value) {
      try {
        getKeyStore().setEntry(alias, value, protectionParameter(alias));
      } catch (final KeyStoreException e) {
        throw new RuntimeKeyStoreException(e);
      }
      return value;
    }

    @SuppressWarnings("unchecked")

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
