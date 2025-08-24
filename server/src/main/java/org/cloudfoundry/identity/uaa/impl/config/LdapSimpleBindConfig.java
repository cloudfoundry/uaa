package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserMapper;
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
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.util.StringUtils;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static java.util.Optional.ofNullable;

@Configuration
@Conditional(LdapSimpleBindConfig.IfConfigured.class)
public class LdapSimpleBindConfig {
    public static class IfConfigured implements Condition {
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String ldapProfileFile = context.getEnvironment().getProperty("ldap.profile.file");
            return ldapProfileFile == null || "ldap/ldap-simple-bind.xml".equals(ldapProfileFile);
        }
    }

    @Bean
    public DefaultSpringSecurityContextSource defaultSpringSecurityContextSource(Environment environment, Map ldapProperties, ProcessLdapProperties ldapPropertyProcessor) throws ClassNotFoundException, KeyManagementException, NoSuchAlgorithmException, InstantiationException, IllegalAccessException {
        String providerUrl = ofNullable(environment.getProperty("ldap.base.url"))
                .orElse("ldap://localhost:389/");
        DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(providerUrl);
        contextSource.setBaseEnvironmentProperties(ldapProperties);
        contextSource.setPooled(false);
        contextSource.setAuthenticationStrategy(ldapPropertyProcessor.getAuthenticationStrategy());
        return contextSource;
    }

    @Bean
    public LdapAuthenticationProvider ldapAuthProvider(BaseLdapPathContextSource contextSource, Environment environment,
            LdapAuthoritiesPopulator ldapAuthoritiesPopulator, GrantedAuthoritiesMapper ldapAuthoritiesMapper,
            ExtendedLdapUserMapper extendedLdapUserDetailsMapper) {
        String userDnPattern = ofNullable(environment.getProperty("ldap.base.userDnPattern"))
                .orElse("cn={0},ou=Users,dc=test,dc=com");
        String userDnPatternLimiter = ofNullable(environment.getProperty("ldap.base.userDnPatternDelimiter"))
                .orElse(";");
        String[] userDnPatterns = StringUtils.delimitedListToStringArray(userDnPattern, userDnPatternLimiter);
        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserDnPatterns(userDnPatterns);
        LdapAuthenticationProvider ldapAuthenticationProvider = new LdapAuthenticationProvider(authenticator, ldapAuthoritiesPopulator);
        ldapAuthenticationProvider.setAuthoritiesMapper(ldapAuthoritiesMapper);
        ldapAuthenticationProvider.setUserDetailsContextMapper(extendedLdapUserDetailsMapper);
        return ldapAuthenticationProvider;
    }

    @Bean
    public String testLdapProfile() {
        return "ldap-simple-bind.xml";
    }
}
