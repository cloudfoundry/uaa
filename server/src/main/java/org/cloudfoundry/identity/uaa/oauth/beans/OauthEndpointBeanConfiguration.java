package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientDetailsAuthenticationProvider;
import org.cloudfoundry.identity.uaa.authentication.ClientParametersAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.CurrentUserCookieRequestFilter;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.CompositeAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.PasswordGrantAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.UserLockoutPolicyRetriever;
import org.cloudfoundry.identity.uaa.client.ClientAuthenticationPublisher;
import org.cloudfoundry.identity.uaa.client.UaaClientDetailsUserDetailsService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.login.CurrentUserCookieFactory;
import org.cloudfoundry.identity.uaa.oauth.ClientAccessTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.ClientRefreshTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.HybridTokenGranterForAuthorizationCode;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationFilter;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.security.CsrfAwareEntryPointAndDeniedHandler;
import org.cloudfoundry.identity.uaa.security.web.TokenEndpointPostProcessor;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.SetFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpSession;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

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

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    ClientAccessTokenValidity clientAccessTokenValidity;

    @Autowired
    DatabaseProperties databaseProperties;

    @Autowired
    DbUtils dbUtils;

    @Autowired
    @Qualifier("jdbcAuditService")
    JdbcAuditService jdbcAuditService;

    @Autowired
    @Qualifier("nonCachingPasswordEncoder")
    PasswordEncoder nonCachingPasswordEncoder;

    @Autowired
    @Qualifier("identityProviderProvisioning")
    IdentityProviderProvisioning providerProvisioning;

    @Bean("cachingPasswordEncoder")
    CachingPasswordEncoder cachingPasswordEncoder(
            @Qualifier("nonCachingPasswordEncoder") PasswordEncoder nonCachingPasswordEncoder
    ) throws NoSuchAlgorithmException {
        return new CachingPasswordEncoder(nonCachingPasswordEncoder);
    }

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
        return new UaaClientDetailsUserDetailsService(jdbcClientDetailsService);
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


    @Bean("userDatabase")
    JdbcUaaUserDatabase userDatabase() throws SQLException {
        return new JdbcUaaUserDatabase(
                jdbcTemplate,
                timeService,
                databaseProperties,
                identityZoneManager,
                dbUtils
        );
    }

    @Bean("userLockoutPolicy")
    LockoutPolicy userLockoutPolicy(
            @Value("${authentication.policy.countFailuresWithinSeconds:#{defaultUserLockoutPolicy.getCountFailuresWithin()}}") int countFailuresWithin,
            @Value("${authentication.policy.lockoutAfterFailures:#{defaultUserLockoutPolicy.getLockoutAfterFailures()}}") int lockoutAfterFailures,
            @Value("${authentication.policy.lockoutPeriodSeconds:#{defaultUserLockoutPolicy.getLockoutPeriodSeconds()}}") int lockoutPeriodSeconds
    ) {
        return new LockoutPolicy(
                countFailuresWithin,
                lockoutAfterFailures,
                lockoutPeriodSeconds
        );
    }

    @Bean("defaultUserLockoutPolicy")
    LockoutPolicy defaultUserLockoutPolicy(@Value("${authentication.policy.global.countFailuresWithinSeconds:1200}") int countFailuresWithin,
                                           @Value("${authentication.policy.global.lockoutAfterFailures:5}") int lockoutAfterFailures,
                                           @Value("${authentication.policy.global.lockoutPeriodSeconds:300}") int lockoutPeriodSeconds
    ) {
        return new LockoutPolicy(
                countFailuresWithin,
                lockoutAfterFailures,
                lockoutPeriodSeconds
        );
    }

    @Bean
    UserLockoutPolicyRetriever globalUserLockoutPolicyRetriever(
            @Autowired @Qualifier("defaultUserLockoutPolicy") LockoutPolicy lockoutPolicy
    ) {
        UserLockoutPolicyRetriever bean = new UserLockoutPolicyRetriever(providerProvisioning);
        bean.setDefaultLockoutPolicy(lockoutPolicy);
        return bean;
    }

    @Bean("globalPeriodLockoutPolicy")
    PeriodLockoutPolicy globalPeriodLockoutPolicy(
            @Autowired @Qualifier("globalUserLoginPolicy") LoginPolicy loginPolicy
    ) {
        return new PeriodLockoutPolicy(loginPolicy);
    }

    @Bean("globalUserLoginPolicy")
    CommonLoginPolicy globalUserLoginPolicy(
            @Autowired UserLockoutPolicyRetriever globalUserLockoutPolicyRetriever
    ) {
        return new CommonLoginPolicy(
                jdbcAuditService,
                globalUserLockoutPolicyRetriever,
                AuditEventType.UserAuthenticationSuccess,
                AuditEventType.UserAuthenticationFailure,
                timeService,
                true
        );
    }

    @Bean("uaaUserDatabaseAuthenticationManager")
    AuthzAuthenticationManager uaaUserDatabaseAuthenticationManager(
            @Autowired JdbcUaaUserDatabase userDatabase,
            @Qualifier("globalPeriodLockoutPolicy") PeriodLockoutPolicy lockoutPolicy,
            @Value("${allowUnverifiedUsers:true}") boolean allowUnverifiedUsers,
            @Autowired HttpSession session,
            @Qualifier("nonCachingPasswordEncoder") PasswordEncoder nonCachingPasswordEncoder
    ) {
        AuthzAuthenticationManager bean = new AuthzAuthenticationManager(
                userDatabase,
                nonCachingPasswordEncoder,
                providerProvisioning,
                session
        );
        bean.setAccountLoginPolicy(lockoutPolicy);
        bean.setOrigin(OriginKeys.UAA);
        bean.setAllowUnverifiedUsers(allowUnverifiedUsers);
        return bean;
    }
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
    @Bean("passwordGrantAuthenticationManager")
    PasswordGrantAuthenticationManager passwordGrantAuthenticationManager(
            @Autowired DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager,
            @Autowired ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager
            ) {
        return new PasswordGrantAuthenticationManager(
                zoneAwareAuthzAuthenticationManager,
                providerProvisioning,
                externalOAuthAuthenticationManager
        );
    }

    @Bean("passcodeAuthenticationFilter")
    PasscodeAuthenticationFilter passcodeAuthenticationFilter(
            @Qualifier("userDatabase") UaaUserDatabase userDatabase,
            @Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
            @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore,
            @Qualifier("authenticationDetailsSource")AuthenticationDetailsSource authenticationDetailsSource
            ) {
        PasscodeAuthenticationFilter bean = new PasscodeAuthenticationFilter(
                userDatabase,
                authenticationManager,
                oAuth2RequestFactory,
                expiringCodeStore
        );
        bean.setAuthenticationDetailsSource(authenticationDetailsSource);
        bean.setParameterNames(
                Arrays.asList(
                        "username",
                        "password",
                        "passcode",
                        "credentials",
                        "origin",
                        "user_id"
                )
        );
        return bean;
    }

    @Bean("passcodeTokenMatcher")
    UaaRequestMatcher passcodeTokenMatcher() {
        UaaRequestMatcher bean = new UaaRequestMatcher("/oauth/token");
        bean.setAccept(asList(MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
        bean.setParameters(Map.ofEntries(
                entry("grant_type", "password"),
                entry("passcode", "")
        ));
        return bean;
    }

    @Bean("hybridTokenGranterForAuthCodeGrant")
    HybridTokenGranterForAuthorizationCode hybridTokenGranterForAuthCodeGrant(
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory authorizationRequestManager
    ) {
        return new HybridTokenGranterForAuthorizationCode(
                tokenServices,
                jdbcClientDetailsService,
                authorizationRequestManager
        );
    }

    @Bean("oauthTokenApiRequestMatcher")
    UaaRequestMatcher oauthTokenApiRequestMatcher() {
        UaaRequestMatcher bean = new UaaRequestMatcher("/oauth/token");
        bean.setHeaders(Map.ofEntries(
                entry("Authorization", asList("bearer "))
        ));
        bean.setParameters(Map.ofEntries(
                entry("client_id", "")
        ));
        return bean;
    }

    @Bean("clientAuthenticationFilter")
    ClientBasicAuthenticationFilter clientAuthenticationFilter(
            @Qualifier("clientAuthenticationManager") AuthenticationManager clientAuthenticationManager,
            @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint basicAuthenticationEntryPoint,
            @Value("${authentication.enableUriEncodingCompatibilityMode:false}") boolean enableUriEncodingCompatibilityMod,
            @Qualifier("authenticationDetailsSource")AuthenticationDetailsSource authenticationDetailsSource
    ) {
        ClientBasicAuthenticationFilter bean = new ClientBasicAuthenticationFilter(
                clientAuthenticationManager,
                basicAuthenticationEntryPoint,
                enableUriEncodingCompatibilityMod
        );
        bean.setAuthenticationDetailsSource(authenticationDetailsSource);
        return bean;
    }

    @Bean("clientParameterAuthenticationFilter")
    ClientParametersAuthenticationFilter clientParameterAuthenticationFilter(
            @Qualifier("clientAuthenticationManager") AuthenticationManager clientAuthenticationManager,
            @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint basicAuthenticationEntryPoint
    ) {
        ClientParametersAuthenticationFilter bean = new ClientParametersAuthenticationFilter();
        bean.setAuthenticationEntryPoint(basicAuthenticationEntryPoint);
        bean.setClientAuthenticationManager(clientAuthenticationManager);
        return bean;
    }

    @Bean("compositeAuthenticationManager")
    CompositeAuthenticationManager compositeAuthenticationManager() {
        return new CompositeAuthenticationManager();
    }

    @Bean("jwtClientAuthentication")
    JwtClientAuthentication jwtClientAuthentication(
            @Qualifier("keyInfoService") KeyInfoService keyInfoService,
            @Qualifier("oidcMetadataFetcher") OidcMetadataFetcher oidcMetadataFetcher,
            @Qualifier("externalOAuthAuthenticationManager") ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager
    ) {
        return new JwtClientAuthentication(
                keyInfoService,
                oidcMetadataFetcher,
                externalOAuthAuthenticationManager
        );
    }

    @Bean("clientAuthenticationPublisher")
    ClientAuthenticationPublisher clientAuthenticationPublisher() {
        return new ClientAuthenticationPublisher();
    }

    @Bean("clientAuthenticationProvider")
    ClientDetailsAuthenticationProvider clientAuthenticationProvider(
            @Qualifier("clientDetailsUserService") UserDetailsService clientDetailsUserService,
            @Qualifier("cachingPasswordEncoder") PasswordEncoder cachingPasswordEncoder,
            @Qualifier("jwtClientAuthentication") JwtClientAuthentication jwtClientAuthentication
    ) {
        return new ClientDetailsAuthenticationProvider(
                clientDetailsUserService,
                cachingPasswordEncoder,
                jwtClientAuthentication
        );
    }

    @Bean("clientAuthenticationManager")
    AuthenticationManager clientAuthenticationManager(
            @Autowired ClientDetailsAuthenticationProvider provider,
            @Autowired AuthenticationEventPublisher defaultAuthenticationEventPublisher
    ) {
        ProviderManager bean = new ProviderManager(provider);
        bean.setAuthenticationEventPublisher(defaultAuthenticationEventPublisher);
        return bean;
    }

    @Bean("oauthAuthorizeRequestMatcher")
    UaaRequestMatcher oauthAuthorizeRequestMatcher() {
        UaaRequestMatcher bean = new UaaRequestMatcher("/oauth/authorize");
        bean.setAccept(asList(MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
        bean.setParameters(
                Map.ofEntries(
                        entry("response_type", "token"),
                        entry("source", "credentials")
                )
        );
        return bean;
    }

    @Bean("oauthAuthorizeApiRequestMatcher")
    UaaRequestMatcher oauthAuthorizeApiRequestMatcher() {
        UaaRequestMatcher bean = new UaaRequestMatcher("/oauth/authorize");
        bean.setHeaders(Map.ofEntries(
                entry("Authorization", asList("bearer "))
        ));
        bean.setParameters(
                Map.ofEntries(
                        entry("response_type", "code"),
                        entry("client_id", "")
                )
        );
        return bean;
    }

    @Bean("promptOauthAuthorizeApiRequestMatcher")
    UaaRequestMatcher promptOauthAuthorizeApiRequestMatcher() {
        UaaRequestMatcher bean = new UaaRequestMatcher("/oauth/authorize");
        bean.setParameters(
                Map.ofEntries(
                        entry("prompt", "none")
                )
        );
        return bean;
    }
    
    @Bean("authzAuthenticationFilter")
    AuthzAuthenticationFilter authzAuthenticationFilter(
            @Autowired DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager
    ) {
        AuthzAuthenticationFilter bean = new AuthzAuthenticationFilter(zoneAwareAuthzAuthenticationManager);
        bean.setParameterNames(
                asList(
                        "username",
                        "password",
                        "passcode",
                        "credentials"
                )
        );
        return bean;
    }

    @Bean("passwordChangeRequiredFilter")
    PasswordChangeRequiredFilter passwordChangeRequiredFilter(
            @Qualifier("uaaAuthorizationEndpoint") AuthenticationEntryPoint uaaAuthorizationEndpoint
    ) {
        return new PasswordChangeRequiredFilter(uaaAuthorizationEndpoint);
    }

    @Bean("currentUserCookieFilter")
    CurrentUserCookieRequestFilter currentUserCookieFilter(
            @Qualifier("currentUserCookieFactory") CurrentUserCookieFactory currentUserCookieFactory
    ) {
        return new CurrentUserCookieRequestFilter(currentUserCookieFactory);
    }

    @Bean("externalOAuthAuthenticationManager")
    ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager(
        @Qualifier("externalOAuthProviderConfigurator") IdentityProviderProvisioning providerProvisioning,
        @Qualifier("trustingRestTemplate") RestTemplate trustingRestTemplate,
        @Qualifier("nonTrustingRestTemplate") RestTemplate nonTrustingRestTemplate,
        @Qualifier("tokenEndpointBuilder") TokenEndpointBuilder tokenEndpointBuilder,
        @Qualifier("keyInfoService") KeyInfoService keyInfoService,
        @Qualifier("oidcMetadataFetcher") OidcMetadataFetcher oidcMetadataFetcher,
        @Qualifier("userDatabase") UaaUserDatabase userDatabase,
        @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager externalMembershipManager
    ) {
        ExternalOAuthAuthenticationManager bean = new ExternalOAuthAuthenticationManager(
                providerProvisioning,
                trustingRestTemplate,
                nonTrustingRestTemplate,
                tokenEndpointBuilder,
                keyInfoService,
                oidcMetadataFetcher
        );
        bean.setUserDatabase(userDatabase);
        bean.setExternalMembershipManager(externalMembershipManager);
        return bean;
    }

    @Bean("externalOAuthCallbackAuthenticationFilter")
    ExternalOAuthAuthenticationFilter externalOAuthCallbackAuthenticationFilter(
            @Qualifier("externalOAuthAuthenticationManager") ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager,
            @Qualifier("accountSavingAuthenticationSuccessHandler") AccountSavingAuthenticationSuccessHandler successHandler
    ) {
        return new ExternalOAuthAuthenticationFilter(
                externalOAuthAuthenticationManager,
                successHandler
        );
    }

    @Bean("externalOAuthCallbackRequestMatcher")
    UaaRequestMatcher externalOAuthCallbackRequestMatcher() {
        return new UaaRequestMatcher("/login/callback");
    }

    @Bean("oauthAuthorizeRequestMatcherOld")
    UaaRequestMatcher oauthAuthorizeRequestMatcherOld() {
        UaaRequestMatcher bean = new UaaRequestMatcher("/oauth/authorize");
        bean.setAccept(asList(MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
        bean.setParameters(
                Map.ofEntries(
                        entry("response_type", "token"),
                        entry("credentials", "{")
                )
        );
        return bean;
    }



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
