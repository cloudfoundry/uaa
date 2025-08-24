/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.provider.ldap.extension;

import org.springframework.security.core.GrantedAuthority;

import java.util.Map;
import java.util.Objects;

/**
 * An authority that contains at least a DN and a role name for an LDAP entry
 * but can also contain other desired attributes to be fetched during an LDAP
 * authority search.
 *
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
        this(role, dn, null);
    }

    public LdapAuthority(String role, String dn, Map<String, String[]> attributes) {
        if (role == null) {
            throw new NullPointerException("role can not be null");
        }
        this.role = role;
        this.dn = dn;
        this.attributes = attributes;
    }

    public String[] getAttributeValues(String name) {
        String[] result = null;
        if (attributes != null) {
            result = attributes.get(name);
        }
        if (result == null) {
            result = new String[0];
        }
        return result;
    }

    public String getFirstAttributeValue(String name) {
        String[] result = getAttributeValues(name);
        if (result.length > 0) {
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
        if (this == o) {
            return true;
        }
        if (!(o instanceof LdapAuthority that)) {
            return false;
        }

        if (!dn.equals(that.dn)) {
            return false;
        }
        return Objects.equals(role, that.role);
    }

    @Override
    public int hashCode() {
        int result = dn.hashCode();
        result = 31 * result + (role != null ? role.hashCode() : 0);
        return result;
    }
}
