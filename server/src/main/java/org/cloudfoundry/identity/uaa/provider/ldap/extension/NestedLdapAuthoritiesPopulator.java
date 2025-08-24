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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;

/**
 * A LDAP authority populator that can recursively search static nested groups.
 * <p>An example of nested groups can be
 * <pre>
 * dn: ou=groups,dc=springframework,dc=org
 * objectClass: top
 * objectClass: organizationalUnit
 * ou: groups
 *
 * dn: cn=developers,ou=groups,dc=springframework,dc=org
 * objectClass: groupOfNames
 * objectClass: top
 * cn: developers
 * description: Spring Security Developers
 * member: uid=ben,ou=people,dc=springframework,dc=org
 * member: uid=luke,ou=people,dc=springframework,dc=org
 * member: cn=java-developers,ou=groups,dc=springframework,dc=org
 *
 * ou: java-developers
 * dn: cn=java-developers,ou=groups,dc=springframework,dc=org
 * objectClass: groupOfNames
 * objectClass: top
 * cn: developers
 * description: Spring Security Java Developers
 * member: uid=filip,ou=people,dc=springframework,dc=org
 * ou: java-developer
 * </pre>
 * <p>
 * During an authentication
 */
public class NestedLdapAuthoritiesPopulator extends DefaultLdapAuthoritiesPopulator {
    public static final String MEMBER_OF = "memberOf";
    private static final Logger logger = LoggerFactory.getLogger(NestedLdapAuthoritiesPopulator.class);

    private Set<String> attributeNames;

    private int maxSearchDepth = 10;

    /**
     * Constructor for group search scenarios. <tt>userRoleAttributes</tt> may still be
     * set as a property.
     *
     * @param contextSource   supplies the contexts used to search for user roles.
     * @param groupSearchBase if this is an empty string the search will be performed from the root DN of the
     */
    public NestedLdapAuthoritiesPopulator(ContextSource contextSource, String groupSearchBase) {
        super(contextSource, groupSearchBase);
    }

    @Override
    public Collection<GrantedAuthority> getGrantedAuthorities(DirContextOperations user, String username) {
        if (MEMBER_OF.equals(getGroupSearchBase())) {
            String[] memberOfs = user.getStringAttributes(MEMBER_OF);
            if (memberOfs == null || memberOfs.length == 0) {
                return emptyList();
            } else {
                return Arrays.stream(memberOfs).map(s -> new LdapAuthority(s, s)).collect(Collectors.toList());
            }
        } else {
            return super.getGrantedAuthorities(user, username);
        }
    }

    @Override
    public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
        if (getGroupSearchBase() == null) {
            return new HashSet<>();
        }

        Set<GrantedAuthority> authorities = new HashSet<>();

        performNestedSearch(userDn, username, authorities, getMaxSearchDepth());

        return authorities;
    }

    protected void performNestedSearch(String userDn, String username, Set<GrantedAuthority> authorities, int depth) {
        if (depth == 0) {
            //back out of recursion
            logger.debug("Search aborted, max depth reached," +
                    " for roles for user '{}', DN = " + "'{}', with filter {} in search base '{}'", username, userDn, getGroupSearchFilter(), getGroupSearchBase());
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Searching for roles for user '{}', DN = " + "'{}', with filter {} in search base '{}'", username, userDn, getGroupSearchFilter(), getGroupSearchBase());
        }

        if (StringUtils.hasText(getGroupRoleAttribute()) && !getAttributeNames().contains(getGroupRoleAttribute())) {
            getAttributeNames().add(getGroupRoleAttribute());
        }

        Set<Map<String, String[]>> userRoles = getLdapTemplate().searchForMultipleAttributeValues(
                getGroupSearchBase(),
                getGroupSearchFilter(),
                new String[]{userDn, username},
                getAttributeNames().toArray(new String[0]));

        if (logger.isDebugEnabled()) {
            logRoles(userRoles);
        }

        for (Map<String, String[]> record : userRoles) {
            boolean circular = false;
            String dn = record.get(SpringSecurityLdapTemplate.DN_KEY)[0];
            String[] roleValues = record.get(getGroupRoleAttribute());
            Set<String> roles = new HashSet<>(Arrays.asList(roleValues != null ? roleValues : new String[0]));
            for (String role : roles) {
                if (isConvertToUpperCase()) {
                    role = role.toUpperCase();
                }
                role = getRolePrefix() + role;
                circular = circular | (!authorities.add(new LdapAuthority(role, dn, record)));
            }
            String roleName = roles.isEmpty() ? dn : roles.iterator().next();
            if (!circular) {
                performNestedSearch(dn, roleName, authorities, (depth - 1));
            }

        }
    }

    protected void logRoles(Set<Map<String, String[]>> userRoles) {
        int counter = 0;
        StringBuffer logDebug = new StringBuffer();
        for (Map<String, String[]> debugRoles : userRoles) {
            for (String debugRoleKey : debugRoles.keySet()) {
                logDebug.append(++counter);
                logDebug.append(".[");
                logDebug.append("Key:");
                logDebug.append(debugRoleKey);
                logDebug.append(" Values:");
                for (String debugValues : debugRoles.get(debugRoleKey)) {
                    logDebug.append(debugValues);
                    logDebug.append("; ");
                }
                logDebug.append("] ");
            }
        }
        if (counter > 0) {
            logger.debug("Roles from LDAP search:{}", logDebug);
        } else {
            logger.debug("No Roles from LDAP search returned");
        }
    }

    public Set<String> getAttributeNames() {
        return attributeNames;
    }

    public void setAttributeNames(Set<String> attributeNames) {
        this.attributeNames = attributeNames;
    }

    public int getMaxSearchDepth() {
        return maxSearchDepth;
    }

    public void setMaxSearchDepth(int maxSearchDepth) {
        this.maxSearchDepth = maxSearchDepth;
    }


}
