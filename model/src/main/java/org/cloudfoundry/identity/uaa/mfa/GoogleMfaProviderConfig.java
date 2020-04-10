package org.cloudfoundry.identity.uaa.mfa;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class GoogleMfaProviderConfig extends AbstractMfaProviderConfig {

  private String providerDescription;

  public void validate() {
  }

  public String getProviderDescription() {
    return providerDescription;
  }

  public GoogleMfaProviderConfig setProviderDescription(String providerDescription) {
    this.providerDescription = providerDescription;
    return this;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    GoogleMfaProviderConfig that = (GoogleMfaProviderConfig) o;

    if (!Objects.equals(providerDescription, that.providerDescription)) {
      return false;
    }
    return super.equals(that);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result += providerDescription != null ? providerDescription.hashCode() : 0;
    return result;
  }
}
