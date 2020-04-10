package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.annotation.JsonProperty;

public class IntrospectionClaims extends Claims {

  @JsonProperty("active")
  private boolean active;

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }
}
