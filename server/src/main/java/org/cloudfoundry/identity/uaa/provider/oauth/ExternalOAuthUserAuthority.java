package org.cloudfoundry.identity.uaa.provider.oauth;

import org.springframework.security.core.GrantedAuthority;

public class ExternalOAuthUserAuthority implements GrantedAuthority {

  private final String authority;

  public ExternalOAuthUserAuthority(String authority) {
    this.authority = authority;
  }

  @Override
  public String getAuthority() {
    return authority;
  }
}
