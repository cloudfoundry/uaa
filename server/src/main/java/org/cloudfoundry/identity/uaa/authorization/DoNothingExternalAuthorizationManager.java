
package org.cloudfoundry.identity.uaa.authorization;

import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

public class DoNothingExternalAuthorizationManager implements ExternalGroupMappingAuthorizationManager {

    @Override
    public Set<? extends GrantedAuthority> findScopesFromAuthorities(Set<? extends GrantedAuthority> authorities) {
        return authorities;
    }

}
