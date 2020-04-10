
package org.cloudfoundry.identity.uaa.authorization;

import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

public interface ExternalGroupMappingAuthorizationManager {

    Set<? extends GrantedAuthority> findScopesFromAuthorities(Set<? extends GrantedAuthority> authorities);

}
