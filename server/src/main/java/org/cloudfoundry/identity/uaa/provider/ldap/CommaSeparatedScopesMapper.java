
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.provider.ldap.extension.LdapAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;

public class CommaSeparatedScopesMapper implements GrantedAuthoritiesMapper {

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        ArrayList<GrantedAuthority> result = new ArrayList<>();
        for (GrantedAuthority authority : authorities) {
            LdapAuthority ldapAuthority = (LdapAuthority)authority;
            for (String scope : StringUtils.commaDelimitedListToSet(authority.getAuthority())) {
                LdapAuthority a = new LdapAuthority(scope, ldapAuthority.getDn(), ldapAuthority.getAttributes());
                result.add(a);
            }
        }
        return result;
    }
}
