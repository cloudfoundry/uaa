package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.provider.ldap.extension.NestedLdapAuthoritiesPopulator;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import java.util.Collections;
import java.util.HashSet;

import static java.util.Optional.ofNullable;

public class LdapGroupsConfig {
    @Bean
    public LdapAuthoritiesPopulator nestedLdapAuthoritiesPopulator(ContextSource contextSource, Environment environment, String configuredGroupRoleAttribute) {
        String searchBase = ofNullable(environment.getProperty("ldap.groups.searchBase")).orElse("ou=scopes,dc=test,dc=com");
        boolean searchSubtree = ofNullable(environment.getProperty("ldap.groups.searchSubtree")).map(Boolean::parseBoolean).orElse(true);
        String groupSearchFilter = ofNullable(environment.getProperty("ldap.groups.groupSearchFilter")).orElse("member={0}");
        NestedLdapAuthoritiesPopulator nestedLdapAuthoritiesPopulator = new NestedLdapAuthoritiesPopulator(contextSource, searchBase);
        nestedLdapAuthoritiesPopulator.setGroupRoleAttribute(configuredGroupRoleAttribute);
        nestedLdapAuthoritiesPopulator.setSearchSubtree(searchSubtree);
        nestedLdapAuthoritiesPopulator.setRolePrefix("");
        nestedLdapAuthoritiesPopulator.setConvertToUpperCase(false);
        nestedLdapAuthoritiesPopulator.setGroupSearchFilter(groupSearchFilter);
        nestedLdapAuthoritiesPopulator.setMaxSearchDepth(ofNullable(Integer.parseInt(environment.getProperty("ldap.groups.maxSearchDepth"))).orElse(10));
        nestedLdapAuthoritiesPopulator.setAttributeNames(new HashSet<>(Collections.singletonList("cn")));
        nestedLdapAuthoritiesPopulator.setIgnorePartialResultException(ofNullable(environment.getProperty("ldap.groups.ignorePartialResultException")).map(Boolean::parseBoolean).orElse(true));
        return nestedLdapAuthoritiesPopulator;
    }
}
