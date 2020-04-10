package org.cloudfoundry.identity.uaa.util;

public class ObjectUtils {

  public static <T> T castInstance(Object o, Class<T> clazz) {
    try {
      return clazz.cast(o);
    } catch (ClassCastException e) {
      throw new IllegalArgumentException(e);
    }
  }
}
