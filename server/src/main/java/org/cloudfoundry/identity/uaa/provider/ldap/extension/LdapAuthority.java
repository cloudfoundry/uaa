package org.cloudfoundry.identity.uaa.provider.ldap.extension;

import org.springframework.security.core.GrantedAuthority;

import java.util.Map;
import java.util.Objects;

/**
 * An authority that contains at least a DN and a role name for an LDAP entry
 * but can also contain other desired attributes to be fetched during an LDAP
 * authority search.
 * @author Filip Hanik
 */
public class LdapAuthority implements GrantedAuthority {

    public String getDn() {
        return dn;
    }

    private String dn;
    private String role;

    public Map<String, String[]> getAttributes() {
        return attributes;
    }

    private Map<String, String[]> attributes;

    public LdapAuthority(String role, String dn) {
        this(role,dn,null);
    }

    public LdapAuthority(String role, String dn, Map<String,String[]> attributes) {
        if (role==null) throw new NullPointerException("role can not be null");
        this.role = role;
        this.dn = dn;
        this.attributes = attributes;
    }

    public String[] getAttributeValues(String name) {
        String[] result = null;
        if (attributes!=null) {
            result = attributes.get(name);
        }
        if (result==null) {
            result = new String[0];
        }
        return result;
    }

    public String getFirstAttributeValue(String name) {
        String[] result = getAttributeValues(name);
        if (result.length>0) {
            return result[0];
        } else {
            return null;
        }
    }

    @Override
    public String getAuthority() {
        return role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof LdapAuthority)) return false;

        LdapAuthority that = (LdapAuthority) o;

        if (!dn.equals(that.dn)) return false;
        if (!Objects.equals(role, that.role)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = dn.hashCode();
        result = 31 * result + (role != null ? role.hashCode() : 0);
        return result;
    }
}
