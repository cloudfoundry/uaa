package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserMapper;
import org.cloudfoundry.identity.uaa.provider.ldap.PasswordComparisonAuthenticator;
import org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static java.util.Optional.ofNullable;

@Configuration
@Conditional(LdapSearchAndCompareConfig.IfConfigured.class)
public class LdapSearchAndCompareConfig {
    public static class IfConfigured implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String ldapProfileFile = context.getEnvironment().getProperty("ldap.profile.file");
            return "ldap/ldap-search-and-compare.xml".equals(ldapProfileFile);
        }
    }

    @Bean
    public DefaultSpringSecurityContextSource defaultSpringSecurityContextSource(Environment environment, Map ldapProperties,
            ProcessLdapProperties ldapPropertyProcessor) throws ClassNotFoundException, KeyManagementException, NoSuchAlgorithmException, InstantiationException, IllegalAccessException {
        String providerUrl = ofNullable(environment.getProperty("ldap.base.url"))
                .orElse("ldap://localhost:389/dc=test,dc=com");
        DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(providerUrl);
        contextSource.setUserDn(ofNullable(environment.getProperty("ldap.base.userDn"))
                .orElse("cn=admin,ou=Users,dc=test,dc=com"));
        contextSource.setPassword(ofNullable(environment.getProperty("ldap.base.password"))
                .orElse("adminsecret"));
        contextSource.setBaseEnvironmentProperties(ldapProperties);
        contextSource.setPooled(false);
        contextSource.setAuthenticationStrategy(ldapPropertyProcessor.getAuthenticationStrategy());
        return contextSource;
    }

    @Bean
    public LdapAuthenticationProvider ldapAuthProvider(BaseLdapPathContextSource contextSource, Environment environment,
            LdapAuthoritiesPopulator ldapAuthoritiesPopulator, GrantedAuthoritiesMapper ldapAuthoritiesMapper,
            ExtendedLdapUserMapper extendedLdapUserDetailsMapper) throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        PasswordComparisonAuthenticator authenticator = new PasswordComparisonAuthenticator(contextSource);
        String searchBase = ofNullable(environment.getProperty("ldap.base.searchBase"))
                .orElse("dc=test,dc=com");
        String searchFilter = ofNullable(environment.getProperty("ldap.base.searchFilter"))
                .orElse("cn={0}");
        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(searchBase, searchFilter, contextSource);
        String passwordAttributeName = ofNullable(environment.getProperty("ldap.base.passwordAttributeName")).orElse("userPassword");
        String passwordEncoderClassName = ofNullable(environment.getProperty("ldap.base.passwordEncoder")).orElse("org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator");
        PasswordEncoder passwordEncoder = (PasswordEncoder) Class.forName(passwordEncoderClassName).newInstance();
        boolean localCompare = ofNullable(environment.getProperty("ldap.base.localPasswordCompare")).map(Boolean::parseBoolean).orElse(true);
        authenticator.setUserSearch(userSearch);
        authenticator.setPasswordAttributeName(passwordAttributeName);
        authenticator.setPasswordEncoder(passwordEncoder);
        authenticator.setLocalCompare(localCompare);

        LdapAuthenticationProvider ldapAuthenticationProvider = new LdapAuthenticationProvider(authenticator, ldapAuthoritiesPopulator);
        ldapAuthenticationProvider.setAuthoritiesMapper(ldapAuthoritiesMapper);
        ldapAuthenticationProvider.setUserDetailsContextMapper(extendedLdapUserDetailsMapper);
        return ldapAuthenticationProvider;
    }

    @Bean
    public String testLdapProfile() {
        return "ldap-search-and-compare.xml";
    }
}
