package org.cloudfoundry.identity.uaa.provider.saml;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("serial")
public class SamlUserAuthority implements GrantedAuthority {

  private final String authority;

  @JsonCreator
  public SamlUserAuthority(@JsonProperty("authority") String authority) {
    this.authority = authority;
  }

  @Override
  public String getAuthority() {
    return authority;
  }

  @Override
  public String toString() {
    return authority;
  }
}
