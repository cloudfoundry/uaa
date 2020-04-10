package org.cloudfoundry.identity.uaa.provider;

import java.util.Map;

public class KeystoneIdentityProviderDefinition extends ExternalIdentityProviderDefinition {

  public KeystoneIdentityProviderDefinition() {
    this(null);
  }

  public KeystoneIdentityProviderDefinition(Map<String, Object> configuration) {
    setAdditionalConfiguration(configuration);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }
    return true;
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
