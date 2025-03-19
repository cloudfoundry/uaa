package org.cloudfoundry.identity.uaa.oauth.beans;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.authentication.ClientDetailsAuthenticationProvider;
import org.cloudfoundry.identity.uaa.authentication.ClientParametersAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CheckIdpEnabledAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PasswordGrantAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.UserLockoutPolicyRetriever;
import org.cloudfoundry.identity.uaa.client.UaaClientDetailsUserDetailsService;
import org.cloudfoundry.identity.uaa.oauth.ClientAccessTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.ClientRefreshTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.security.CsrfAwareEntryPointAndDeniedHandler;
import org.cloudfoundry.identity.uaa.security.web.TokenEndpointPostProcessor;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.xmlsec.signature.P;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.SetFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;

import static java.util.Arrays.asList;
import static java.util.Map.entry;

@Configuration
public class OauthEndpointBeanConfiguration {

    @Autowired
    @Qualifier("jdbcClientDetailsService")
    MultitenantClientServices jdbcClientDetailsService;

    @Autowired
    @Qualifier("timeService")
    TimeService timeService;

    @Autowired
    @Qualifier("tokenEndpointBuilder")
    TokenEndpointBuilder tokenEndpointBuilder;

    @Autowired
    IdentityZoneManager identityZoneManager;

    @Bean("loginEntryPoint")
    CsrfAwareEntryPointAndDeniedHandler loginEntryPoint() {
        return new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request");
    }

    @Bean
    UaaOauth2RequestValidator oauth2RequestValidator() {
        UaaOauth2RequestValidator bean = new UaaOauth2RequestValidator();
        bean.setClientDetailsService(jdbcClientDetailsService);
        return bean;
    }

    @Bean
    TokenEndpointPostProcessor tokenEndpointPostProcessor() {
        return new TokenEndpointPostProcessor();
    }

    @Bean
    ClientAccessTokenValidity clientAccessTokenValidity() {
        return new ClientAccessTokenValidity(jdbcClientDetailsService, identityZoneManager);
    }

    @Bean
    ClientRefreshTokenValidity clientRefreshTokenValidity() {
        return new ClientRefreshTokenValidity(jdbcClientDetailsService, identityZoneManager);
    }

    @Bean
    TokenValidityResolver accessTokenValidityResolver(
            @Autowired ClientAccessTokenValidity clientAccessTokenValidity,
            @Value("${jwt.token.policy.global.accessTokenValiditySeconds:43200}") int accessTokenValidity
    ) {
        return new TokenValidityResolver(
                clientAccessTokenValidity,
                accessTokenValidity,
                timeService
        );
    }

    @Bean("clientDetailsUserService")
    UaaClientDetailsUserDetailsService clientDetailsUserService() {
        UaaClientDetailsUserDetailsService bean = new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
        return bean;
    }

    @Bean("defaultUserAuthorities")
    SetFactoryBean defaultUserAuthorities(
            @Value("#{@config['oauth']==null ? legacyDefaultUserAuthorities : @config['oauth']['user']==null ? legacyDefaultUserAuthorities: @config['oauth']['user']['authorities']}") Set<String> sourceSet
    ) {
        SetFactoryBean bean = new SetFactoryBean();
        bean.setSourceSet(sourceSet);
        return bean;
    }

    @Bean("legacyDefaultUserAuthorities")
    HashSet<String> legacyDefaultUserAuthorities() {
        return new LinkedHashSet<>(Arrays.asList(
                "openid",
                "scim.me",
                "cloud_controller.read",
                "cloud_controller.write",
                "password.write",
                "scim.userids",
                "uaa.user",
                "approvals.me",
                "oauth.approvals",
                "cloud_controller_service_permissions.read"
        ));
    }
//
//    @Bean("userDatabase")
//    JdbcUaaUserDatabase userDatabase() {
//
//    }
//
//    @Bean("userLockoutPolicy")
//    LockoutPolicy userLockoutPolicy() {
//
//    }
//
//    @Bean("defaultUserLockoutPolicy")
//    LockoutPolicy defaultUserLockoutPolicy() {
//
//    }
//
//    @Bean("globalUserLockoutPolicyRetriever")
//    UserLockoutPolicyRetriever globalUserLockoutPolicyRetriever() {
//
//    }
//
//    @Bean("globalPeriodLockoutPolicy")
//    PeriodLockoutPolicy globalPeriodLockoutPolicy() {
//
//    }
//
//    @Bean("globalUserLoginPolicy")
//    CommonLoginPolicy globalUserLoginPolicy() {
//
//    }
//
//    @Bean("uaaUserDatabaseAuthenticationManager")
//    AuthzAuthenticationManager uaaUserDatabaseAuthenticationManager() {
//
//    }
//
//    @Bean("uaaAuthenticationMgr")
//    CheckIdpEnabledAuthenticationManager uaaAuthenticationMgr() {
//
//    }
//
//    @Bean("zoneAwareAuthzAuthenticationManager")
//    DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager() {
//
//    }
//
//    @Bean("passwordGrantAuthenticationManager")
//    PasswordGrantAuthenticationManager passwordGrantAuthenticationManager() {
//
//    }
//
//    @Bean("passcodeAuthenticationFilter")
//    PasscodeAuthenticationFilter passcodeAuthenticationFilter() {
//        PasscodeAuthenticationFilter bean = new PasscodeAuthenticationFilter(
//                userDatabase,
//                );
//    }
//
//    @Bean("passcodeTokenMatcher")
//    UaaRequestMatcher passcodeTokenMatcher() {
//        UaaRequestMatcher bean = new UaaRequestMatcher("/oauth/token");
//        bean.setAccept(asList(MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
//        bean.setParameters(Map.ofEntries(
//                entry("grant_type", "password"),
//                entry("passcode", "")
//        ));
//        return bean;
//    }
//
//    @Bean("clientAuthenticationProvider")
//    ClientDetailsAuthenticationProvider clientAuthenticationProvider() {
//        ClientDetailsAuthenticationProvider bean = new ClientDetailsAuthenticationProvider();
//    }
//
//    @Bean("clientParameterAuthenticationFilter")
//    ClientParametersAuthenticationFilter clientParameterAuthenticationFilter() {
//        ClientParametersAuthenticationFilter bean = new ClientParametersAuthenticationFilter();
//
//
//    }


//    @Bean
//    UaaTokenServices tokenServices() {
//        <constructor-arg name="idTokenCreator" ref="idTokenCreator"/>
//        <constructor-arg name="tokenEndpointBuilder" ref="tokenEndpointBuilder"/>
//        <constructor-arg name="clientDetailsService" ref="jdbcClientDetailsService"/>
//        <constructor-arg name="revocableTokenProvisioning" ref="revocableTokenProvisioning"/>
//        <constructor-arg name="tokenValidationService" ref="tokenValidationService"/>
//        <constructor-arg name="refreshTokenCreator" ref="refreshTokenCreator"/>
//        <constructor-arg name="timeService" ref="timeService"/>
//        <constructor-arg name="accessTokenValidityResolver" ref="accessTokenValidityResolver"/>
//        <constructor-arg name="userDatabase" ref="userDatabase"/>
//        <constructor-arg name="approvalService" ref="approvalService"/>
//        <constructor-arg name="excludedClaims" ref="excludedClaims"/>
//        <constructor-arg name="globalTokenPolicy" ref="globalTokenPolicy"/>
//        <constructor-arg name="keyInfoService" ref="keyInfoService"/>
//        <constructor-arg name="idTokenGranter" ref="idTokenGranter"/>
//    }
}
