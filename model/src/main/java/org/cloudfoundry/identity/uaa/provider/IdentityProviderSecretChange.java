package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdentityProviderSecretChange {

  private String secret;

  public String getSecret() {
    return this.secret;
  }

  public void setSecret(final String secret) {
    this.secret = secret;
  }
}
