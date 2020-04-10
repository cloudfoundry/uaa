
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.authorization.ExternalGroupMappingAuthorizationManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Collection;
import java.util.HashSet;

public class LdapGroupToScopesMapper implements GrantedAuthoritiesMapper {

    public ExternalGroupMappingAuthorizationManager getGroupMapper() {
        return groupMapper;
    }

    public void setGroupMapper(ExternalGroupMappingAuthorizationManager groupMapper) {
        this.groupMapper = groupMapper;
    }

    private ExternalGroupMappingAuthorizationManager groupMapper;

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return getGroupMapper().findScopesFromAuthorities(new HashSet<>(authorities));
    }
}
