package com.tersesystems.securitybuilder;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.util.Objects;
import org.slieb.throwables.SupplierWithThrowable;

public abstract class InstanceGenerator<I, E extends Exception> {

  FactoryInstance getInstance() {
    return new FactoryInstance();
  }

  class FactoryInstance {

    private final Class<I> clazz;

    @SuppressWarnings("unchecked")
    private FactoryInstance() {
      this.clazz =
          (Class<I>)
              ((ParameterizedType) InstanceGenerator.this.getClass().getGenericSuperclass())
                  .getActualTypeArguments()[0];
    }


    private Class<I> getClazz() {
      return clazz;
    }


    SupplierWithThrowable<I, E> withAlgorithm(final String algorithm) {
      Objects.requireNonNull(algorithm);
      return () -> singleGetInstance(algorithm);
    }


    SupplierWithThrowable<I, E> withType(final String type) {
      Objects.requireNonNull(type);
      return () -> singleGetInstance(type);
    }


    SupplierWithThrowable<I, E> withProtocol(final String protocol) {
      Objects.requireNonNull(protocol);
      return () -> singleGetInstance(protocol);
    }


    SupplierWithThrowable<I, E> withProtocolAndProvider(
        final String protocol, final String provider) {
      Objects.requireNonNull(protocol);
      return () -> doubleGetInstance(protocol, provider);
    }


    SupplierWithThrowable<I, E> withDefaultAlgorithm() {
      return () -> singleGetInstanceWithDefault("getDefaultAlgorithm");
    }


    SupplierWithThrowable<I, E> withDefaultType() {
      return () -> singleGetInstanceWithDefault("getDefaultType");
    }


    SupplierWithThrowable<I, E> withAlgorithmAndProvider(
        final String algorithm, final String provider) {
      Objects.requireNonNull(algorithm);
      return () -> doubleGetInstance(algorithm, provider);
    }


    SupplierWithThrowable<I, E> withTypeAndProvider(final String type, final String provider) {
      Objects.requireNonNull(type);
      return () -> doubleGetInstance(type, provider);
    }


    @SuppressWarnings("unchecked")
    private I singleGetInstance(final String stringParam) {
      try {
        final Method getInstance = getClazz().getMethod("getInstance", String.class);
        return (I) getInstance.invoke(null, stringParam);
      } catch (
          final NoSuchMethodException
              | IllegalAccessException
              | InvocationTargetException e) {
        throw new RuntimeException(e);
      }
    }


    @SuppressWarnings("unchecked")
    private I doubleGetInstance(final String stringParam, final String provider) {
      try {
        final Method getInstance = getClazz().getMethod("getInstance", String.class, String.class);
        return (I) getInstance.invoke(null, stringParam, provider);
      } catch (
          final NoSuchMethodException
              | IllegalAccessException
              | InvocationTargetException e) {
        throw new RuntimeException(e);
      }
    }


    @SuppressWarnings("unchecked")
    private I singleGetInstanceWithDefault(final String defaultMethodName) {
      try {
        final Method defaultAlgorithmMethod = getClazz().getMethod(defaultMethodName);
        final String defaultAlgorithm = (String) defaultAlgorithmMethod.invoke(null);
        final Method getInstance = getClazz().getMethod("getInstance", String.class);
        return (I) getInstance.invoke(null, defaultAlgorithm);
      } catch (
          final NoSuchMethodException
              | IllegalAccessException
              | InvocationTargetException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
