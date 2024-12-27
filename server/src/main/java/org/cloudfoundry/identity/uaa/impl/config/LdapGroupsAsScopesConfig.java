package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.provider.ldap.CommaSeparatedScopesMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Optional;

@Configuration
@Conditional(LdapGroupsAsScopesConfig.IfConfigured.class)
@Import(LdapGroupsConfig.class)
public class LdapGroupsAsScopesConfig {

    public static class IfConfigured implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String ldapGroupsFile = context.getEnvironment().getProperty("ldap.groups.file");
            return "ldap/ldap-groups-as-scopes.xml".equals(ldapGroupsFile);
        }
    }

    @Bean
    public String configuredGroupRoleAttribute(Environment environment) {
        return Optional.ofNullable(environment.getProperty("ldap.groups.groupRoleAttribute")).orElse("description");
    }

    @Bean
    public GrantedAuthoritiesMapper ldapAuthoritiesMapper() {
        return new CommaSeparatedScopesMapper();
    }

    @Bean
    public String testLdapGroup() {
        return "ldap-groups-as-scopes.xml";
    }
}
