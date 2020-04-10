package org.cloudfoundry.identity.uaa.authorization;

import java.util.Set;
import org.springframework.security.core.GrantedAuthority;

public interface ExternalGroupMappingAuthorizationManager {

  Set<? extends GrantedAuthority> findScopesFromAuthorities(
      Set<? extends GrantedAuthority> authorities);
}
