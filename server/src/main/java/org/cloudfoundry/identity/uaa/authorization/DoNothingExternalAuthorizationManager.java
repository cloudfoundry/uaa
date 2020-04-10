package org.cloudfoundry.identity.uaa.authorization;

import java.util.Set;
import org.springframework.security.core.GrantedAuthority;

public class DoNothingExternalAuthorizationManager
    implements ExternalGroupMappingAuthorizationManager {

  @Override
  public Set<? extends GrantedAuthority> findScopesFromAuthorities(
      Set<? extends GrantedAuthority> authorities) {
    return authorities;
  }
}
