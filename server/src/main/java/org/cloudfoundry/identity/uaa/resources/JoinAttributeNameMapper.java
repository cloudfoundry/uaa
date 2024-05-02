package org.cloudfoundry.identity.uaa.resources;

public class JoinAttributeNameMapper implements AttributeNameMapper {

  private final String customPrefix;
  private final String joinPrefix;
  private final int prefixLength;

  public JoinAttributeNameMapper(String prefix) {
    customPrefix = prefix;
    joinPrefix = prefix + ".";
    prefixLength = joinPrefix.length();
  }

  @Override
  public String mapToInternal(String attr) {
    return joinPrefix + attr;
  }

  @Override
  public String mapFromInternal(String attr) {
    return attr.substring(prefixLength);
  }

  public String getCustomPrefix() {
    return customPrefix;
  }
}
