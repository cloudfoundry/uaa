package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.authorization.LdapGroupMappingAuthorizationManager;
import org.cloudfoundry.identity.uaa.provider.ldap.LdapGroupToScopesMapper;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

@Configuration
@Conditional(LdapGroupsMappedToScopesConfig.IfConfigured.class)
@Import(LdapGroupsConfig.class)
public class LdapGroupsMappedToScopesConfig {

    public static class IfConfigured implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String ldapGroupsFile = context.getEnvironment().getProperty("ldap.groups.file");
            return "ldap/ldap-groups-map-to-scopes.xml".equals(ldapGroupsFile);
        }
    }

    @Bean
    public String configuredGroupRoleAttribute() {
        return "spring.security.ldap.dn";
    }

    @Bean
    public LdapGroupMappingAuthorizationManager ldapGroupMappingAuthorizationManager(ScimGroupExternalMembershipManager externalMembershipManager, ScimGroupProvisioning provisioning) {
        LdapGroupMappingAuthorizationManager ldapGroupMappingAuthorizationManager = new LdapGroupMappingAuthorizationManager();
        ldapGroupMappingAuthorizationManager.setExternalMembershipManager(externalMembershipManager);
        ldapGroupMappingAuthorizationManager.setScimGroupProvisioning(provisioning);
        return ldapGroupMappingAuthorizationManager;
    }

    @Bean
    public GrantedAuthoritiesMapper ldapAuthoritiesMapper(LdapGroupMappingAuthorizationManager ldapGroupMappingAuthorizationManager) {
        LdapGroupToScopesMapper ldapGroupToScopesMapper = new LdapGroupToScopesMapper();
        ldapGroupToScopesMapper.setGroupMapper(ldapGroupMappingAuthorizationManager);
        return ldapGroupToScopesMapper;
    }

    @Bean
    public String testLdapGroup() {
        return "ldap-groups-map-to-scopes.xml";
    }
}
