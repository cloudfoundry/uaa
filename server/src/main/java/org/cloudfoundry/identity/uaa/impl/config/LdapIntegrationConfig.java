package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserMapper;
import org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static java.lang.Boolean.parseBoolean;
import static java.util.Optional.ofNullable;

@Configuration
public class LdapIntegrationConfig {
    public static final String CONNECT_TIMEOUT_MILLIS_KEY =
            "com.sun.jndi.ldap.connect.timeout";
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofMinutes(30);

    @Bean
    public ProcessLdapProperties ldapPropertyProcessor(Environment environment) {
        boolean skipSslVerification = parseBoolean(environment.getProperty("ldap.ssl.skipverification"));
        String baseUrl = ofNullable(environment.getProperty("ldap.base.url")).orElse("ldap://localhost:389/dc=test,dc=com");
        String tlsConfig = ofNullable(environment.getProperty("ldap.ssl.tls")).orElse("none");
        return new ProcessLdapProperties(baseUrl, skipSslVerification, tlsConfig);
    }

    @Bean
    public Map ldapProperties(Environment environment) {
        Map initialLdapProperties = new HashMap();
        initialLdapProperties.put("com.sun.jndi.ldap.connect.pool", false);
        initialLdapProperties.put(CONNECT_TIMEOUT_MILLIS_KEY,
                String.valueOf(DEFAULT_CONNECT_TIMEOUT.toMillis()));
        initialLdapProperties.put("java.naming.referral", ofNullable(environment.getProperty("ldap.base.referral")).orElse("follow"));
        return ldapPropertyProcessor(environment).process(initialLdapProperties);
    }

    @Bean
    public ExtendedLdapUserMapper extendedLdapUserDetailsMapper(Environment environment) {
        String mailAttributeName = ofNullable(environment.getProperty("ldap.base.mailAttributeName")).orElse("mail");
        String givenNameAttributeName = ofNullable(environment.getProperty("ldap.attributeMappings.first_name")).orElse("givenname");
        String familyNameAttributeName = ofNullable(environment.getProperty("ldap.attributeMappings.family_name")).orElse("sn");
        String phoneNumberAttributeName = ofNullable(environment.getProperty("ldap.attributeMappings.phone_number")).orElse("telephonenumber");
        String verifiedAttributeName = ofNullable(environment.getProperty("ldap.attributeMappings.email_verified")).orElse("email_verified");
        String mailSubstitute = environment.getProperty("ldap.base.mailSubstitute");
        boolean mailSubstituteOverridesLdap = parseBoolean(environment.getProperty("ldap.base.mailSubstituteOverridesLdap"));

        ExtendedLdapUserMapper extendedLdapUserDetailsMapper = new ExtendedLdapUserMapper();
        extendedLdapUserDetailsMapper.setEmailVerifiedAttributeName(verifiedAttributeName);
        extendedLdapUserDetailsMapper.setMailAttributeName(mailAttributeName);
        extendedLdapUserDetailsMapper.setGivenNameAttributeName(givenNameAttributeName);
        extendedLdapUserDetailsMapper.setFamilyNameAttributeName(familyNameAttributeName);
        extendedLdapUserDetailsMapper.setPhoneNumberAttributeName(phoneNumberAttributeName);
        extendedLdapUserDetailsMapper.setMailSubstitute(mailSubstitute);
        extendedLdapUserDetailsMapper.setMailSubstituteOverridesLdap(mailSubstituteOverridesLdap);

        return extendedLdapUserDetailsMapper;
    }
}
