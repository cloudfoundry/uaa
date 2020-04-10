package org.cloudfoundry.identity.uaa.util;

import java.util.Enumeration;

public class EmptyEnumerationOfString implements Enumeration<String> {

  public static final EmptyEnumerationOfString EMPTY_ENUMERATION = new EmptyEnumerationOfString();

  @Override
  public boolean hasMoreElements() {
    return false;
  }

  @Override
  public String nextElement() {
    return null;
  }
}
