package org.cloudfoundry.identity.uaa.impl.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.ldap.authentication.NullLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

@Configuration
@Conditional(LdapGroupsNullConfig.IfConfigured.class)
public class LdapGroupsNullConfig {

    public static class IfConfigured implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String ldapGroupsFile = context.getEnvironment().getProperty("ldap.groups.file");
            return ldapGroupsFile == null || "ldap/ldap-groups-null.xml".equals(ldapGroupsFile);
        }
    }

    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
        return new NullLdapAuthoritiesPopulator();
    }

    @Bean
    public GrantedAuthoritiesMapper ldapAuthoritiesMapper() {
        return new SimpleAuthorityMapper();
    }

    @Bean
    public String testLdapGroup() {
        return "ldap-groups-null.xml";
    }
}
