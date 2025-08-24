package org.cloudfoundry.identity.uaa.oauth.beans;

import jakarta.servlet.http.HttpSession;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientDetailsAuthenticationProvider;
import org.cloudfoundry.identity.uaa.authentication.CurrentUserCookieRequestFilter;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CheckIdpEnabledAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.CompositeAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LdapLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.PasswordGrantAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.UserLockoutPolicyRetriever;
import org.cloudfoundry.identity.uaa.client.ClientAuthenticationPublisher;
import org.cloudfoundry.identity.uaa.client.UaaClientDetailsUserDetailsService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.login.CurrentUserCookieFactory;
import org.cloudfoundry.identity.uaa.oauth.ClientAccessTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.ClientRefreshTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.ClientTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.HybridTokenGranterForAuthorizationCode;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidationService;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenStore;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationFilter;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenExchangeWrapperForExternalOauth;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.security.CsrfAwareEntryPointAndDeniedHandler;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.web.TokenEndpointPostProcessor;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserApprovalHandler;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.SetFactoryBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
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

import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collection;
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

    @Autowired
    @Qualifier("dataSource")
    DataSource dataSource;

    @Autowired
    @Qualifier("limitSqlAdapter")
    LimitSqlAdapter limitSqlAdapter;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

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
    FilterRegistrationBean<PasscodeAuthenticationFilter> passcodeAuthenticationFilter(
            @Qualifier("userDatabase") UaaUserDatabase userDatabase,
            @Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager,
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
            @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore,
            @Qualifier("authenticationDetailsSource")AuthenticationDetailsSource authenticationDetailsSource
            ) {
        PasscodeAuthenticationFilter filter = new PasscodeAuthenticationFilter(
                userDatabase,
                authenticationManager,
                oAuth2RequestFactory,
                expiringCodeStore
        );
        filter.setAuthenticationDetailsSource(authenticationDetailsSource);
        filter.setParameterNames(
                Arrays.asList(
                        "username",
                        "password",
                        "passcode",
                        "credentials",
                        "origin",
                        "user_id"
                )
        );
        FilterRegistrationBean<PasscodeAuthenticationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
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
    FilterRegistrationBean<ClientBasicAuthenticationFilter> clientAuthenticationFilter(
            @Qualifier("clientAuthenticationManager") AuthenticationManager clientAuthenticationManager,
            @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint basicAuthenticationEntryPoint,
            @Value("${authentication.enableUriEncodingCompatibilityMode:false}") boolean enableUriEncodingCompatibilityMod,
            @Qualifier("authenticationDetailsSource")AuthenticationDetailsSource authenticationDetailsSource
    ) {
        ClientBasicAuthenticationFilter filter = new ClientBasicAuthenticationFilter(
                clientAuthenticationManager,
                basicAuthenticationEntryPoint,
                enableUriEncodingCompatibilityMod
        );
        filter.setAuthenticationDetailsSource(authenticationDetailsSource);
        FilterRegistrationBean<ClientBasicAuthenticationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
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
    FilterRegistrationBean<AuthzAuthenticationFilter> authzAuthenticationFilter(
            @Autowired DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager
    ) {
        AuthzAuthenticationFilter filter = new AuthzAuthenticationFilter(zoneAwareAuthzAuthenticationManager);
        filter.setParameterNames(
                asList(
                        "username",
                        "password",
                        "passcode",
                        "credentials"
                )
        );
        FilterRegistrationBean<AuthzAuthenticationFilter> bean = new FilterRegistrationBean<AuthzAuthenticationFilter>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean("passwordChangeRequiredFilter")
    FilterRegistrationBean<PasswordChangeRequiredFilter> passwordChangeRequiredFilter(
            @Qualifier("uaaAuthorizationEndpoint") AuthenticationEntryPoint uaaAuthorizationEndpoint
    ) {
        PasswordChangeRequiredFilter filter = new PasswordChangeRequiredFilter(uaaAuthorizationEndpoint);
        FilterRegistrationBean<PasswordChangeRequiredFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean("currentUserCookieFilter")
    FilterRegistrationBean<CurrentUserCookieRequestFilter> currentUserCookieFilter(
            @Qualifier("currentUserCookieFactory") CurrentUserCookieFactory currentUserCookieFactory
    ) {
        CurrentUserCookieRequestFilter filter = new CurrentUserCookieRequestFilter(currentUserCookieFactory);
        FilterRegistrationBean<CurrentUserCookieRequestFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;

    }

    @Bean("externalOAuthAuthenticationManager")
    ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager(
        @Qualifier("externalOAuthProviderConfigurator") IdentityProviderProvisioning providerProvisioning,
        @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
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
                identityZoneManager,
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

    @Bean("tokenExchangeAuthenticationManager")
    @ConditionalOnMissingBean(name = {"tokenExchangeAuthenticationManager"})
    @SuppressWarnings("unchecked")
    AuthenticationManager tokenExchangeAuthenticationManager(
            @Qualifier("externalOAuthAuthenticationManager") final ExternalOAuthAuthenticationManager authenticationManager
    ) {
        return new TokenExchangeWrapperForExternalOauth(authenticationManager);
    }

    @Bean("externalOAuthCallbackAuthenticationFilter")
    FilterRegistrationBean<ExternalOAuthAuthenticationFilter> externalOAuthCallbackAuthenticationFilter(
            @Qualifier("externalOAuthAuthenticationManager") ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager,
            @Qualifier("accountSavingAuthenticationSuccessHandler") AccountSavingAuthenticationSuccessHandler successHandler
    ) {
        ExternalOAuthAuthenticationFilter filter = new ExternalOAuthAuthenticationFilter(
                externalOAuthAuthenticationManager,
                successHandler
        );
        FilterRegistrationBean<ExternalOAuthAuthenticationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;

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

    @Bean("authorizationCodeServices")
    @DependsOnDatabaseInitialization
    UaaTokenStore authorizationCodeServices() {
        return new UaaTokenStore(dataSource, timeService, identityZoneManager);
    }

    @Bean("userApprovalHandler")
    UaaUserApprovalHandler userApprovalHandler(
            @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
            @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices

    ) {
        return new UaaUserApprovalHandler(
                jdbcClientDetailsService,
                oAuth2RequestFactory,
                tokenServices,
                identityZoneManager
        );
    }

    @Bean("authorizationRequestManager")
    UaaAuthorizationRequestManager authorizationRequestManager(
            @Qualifier("userDatabase") UaaUserDatabase userDatabase,
            SecurityContextAccessor securityContextAccessor
    ) {
        return new UaaAuthorizationRequestManager(
                jdbcClientDetailsService,
                securityContextAccessor,
                userDatabase,
                providerProvisioning,
                identityZoneManager
        );
    }

    @Bean("excludedClaims") //TODO break into a record or object
    LinkedHashSet<String> excludedClaims(
            @Value("#{@config['jwt']==null ? T(java.util.Collections).EMPTY_SET : " +
                    "@config['jwt.token']==null ? T(java.util.Collections).EMPTY_SET : " +
                    "@config['jwt.token.claims']==null ? T(java.util.Collections).EMPTY_SET : " +
                    "@config['jwt.token.claims.exclude']==null ? T(java.util.Collections).EMPTY_SET : @config['jwt.token.claims.exclude']}") Collection<String> excludedClaims
    ) {
        return new LinkedHashSet<>(excludedClaims);
    }
    @Bean("signingKeysMap") //TODO break into a record or object
    Map signingKeysMap(
            @Value("#{@config['jwt']==null ? T(java.util.Collections).EMPTY_MAP : " +
                   "@config['jwt.token']==null ? T(java.util.Collections).EMPTY_MAP :" +
                   "@config['jwt.token.policy']==null ? T(java.util.Collections).EMPTY_MAP :" +
                   "@config['jwt.token.policy.keys']==null ? T(java.util.Collections).EMPTY_MAP : @config['jwt.token.policy.keys']}")
            Map<String, ? extends Map<String, String>> signingKeysMap
    ) {
        return signingKeysMap;
    }
    @Bean("uaaTokenPolicy")
    TokenPolicy uaaTokenPolicy(
            @Value("${jwt.token.policy.accessTokenValiditySeconds:#{globalTokenPolicy.getAccessTokenValidity()}}") int accessTokenValidity,
            @Value("${jwt.token.policy.refreshTokenValiditySeconds:#{globalTokenPolicy.getRefreshTokenValidity()}}") int refreshTokenValidity,
            @Qualifier("signingKeysMap") Map signingKeysMap,
            @Value("${jwt.token.policy.activeKeyId:#{null}}") String activeKeyId,
            @Value("${jwt.token.revocable:false}") boolean jwtRevocable,
            @Value("${jwt.token.refresh.format:#{T(org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat).OPAQUE.getStringValue()}}") String refreshTokenFormat,
            @Value("${jwt.token.refresh.unique:false}") boolean refreshTokenUnique,
            @Value("${jwt.token.refresh.rotate:false}") boolean refreshTokenRotate
    ) {
        TokenPolicy bean = new TokenPolicy(
                accessTokenValidity,
                refreshTokenValidity,
                signingKeysMap
        );
        bean.setActiveKeyId(activeKeyId);
        bean.setJwtRevocable(jwtRevocable);
        bean.setRefreshTokenFormat(refreshTokenFormat);
        bean.setRefreshTokenUnique(refreshTokenUnique);
        bean.setRefreshTokenRotate(refreshTokenRotate);
        return bean;
    }

    @Bean("legacyTokenKeyInitializer")
    @DependsOn({"setUpBouncyCastle"})
    KeyInfo legacyTokenKeyInitializer(
            @Value("${uaa.url}") String uaaUrl,
            @Value("${jwt.token.signing-key:#{null}}") String signingKey,
            @Value("${jwt.token.signing-alg:#{null}}") String signingAlg,
            @Value("${jwt.token.signing-cert:#{null}}") String signingCert
    ) {
        LegacyTokenKey.setLegacySigningKey(signingKey, uaaUrl, signingAlg, signingCert);
        return LegacyTokenKey.getLegacyTokenKeyInfo();
    }

    @Bean("globalTokenPolicy")
    TokenPolicy globalTokenPolicy(
           @Value("${jwt.token.policy.global.accessTokenValiditySeconds:43200}") int accessTokenValidity,
           @Value("${jwt.token.policy.global.refreshTokenValiditySeconds:2592000}") int refreshTokenValidity
    ) {
        return new TokenPolicy(accessTokenValidity, refreshTokenValidity);
    }

    @Bean("revocableTokenProvisioning")
    JdbcRevocableTokenProvisioning revocableTokenProvisioning(
            @Value("${delete.expirationRunTime:2500}") int maxExpirationRuntime
    ) {
        JdbcRevocableTokenProvisioning bean = new JdbcRevocableTokenProvisioning(jdbcTemplate, limitSqlAdapter, timeService);
        bean.setMaxExpirationRuntime(maxExpirationRuntime);
        return bean;
    }

    @Bean("refreshTokenValidityResolver")
    TokenValidityResolver refreshTokenValidityResolver(
            @Qualifier("clientRefreshTokenValidity") ClientTokenValidity clientRefreshTokenValidity,
            @Value("${jwt.token.policy.global.refreshTokenValiditySeconds:2592000}") int globalTokenValiditySeconds
    ) {
        return new TokenValidityResolver(
                clientRefreshTokenValidity,
                globalTokenValiditySeconds,
                timeService
        );
    }

    @Bean("oauthAccessDeniedHandler")
    OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {
        return new OAuth2AccessDeniedHandler();
    }

    @Bean("idTokenCreator")
    IdTokenCreator idTokenCreator(
            @Qualifier("tokenEndpointBuilder") TokenEndpointBuilder tokenEndpointBuilder,
            @Qualifier("accessTokenValidityResolver") TokenValidityResolver tokenValidityResolver,
            @Qualifier("userDatabase") UaaUserDatabase uaaUserDatabase,
            @Qualifier("excludedClaims") Set<String> excludedClaims
    ) {
        return new IdTokenCreator(
                tokenEndpointBuilder,
                timeService,
                tokenValidityResolver,
                uaaUserDatabase,
                jdbcClientDetailsService,
                excludedClaims,
                identityZoneManager
        );
    }

    @Bean("refreshTokenCreator")
    RefreshTokenCreator refreshTokenCreator(
            @Value("${jwt.token.refresh.restrict_grant:false}") boolean isRestrictRefreshGrant,
            @Qualifier("refreshTokenValidityResolver") TokenValidityResolver tokenValidityResolver,
            @Qualifier("tokenEndpointBuilder") TokenEndpointBuilder tokenEndpointBuilder,
            @Qualifier("keyInfoService") KeyInfoService keyInfoService
    ) {
        return new RefreshTokenCreator(
                isRestrictRefreshGrant,
                tokenValidityResolver,
                tokenEndpointBuilder,
                timeService,
                keyInfoService
        );
    }

    @Bean("tokenValidationService")
    TokenValidationService tokenValidationService(
            @Qualifier("revocableTokenProvisioning") RevocableTokenProvisioning revocableTokenProvisioning,
            @Qualifier("tokenEndpointBuilder") TokenEndpointBuilder tokenEndpointBuilder,
            @Qualifier("userDatabase") UaaUserDatabase uaaUserDatabase,
            @Qualifier("keyInfoService") KeyInfoService keyInfoService
    ) {
        return new TokenValidationService(
                revocableTokenProvisioning,
                tokenEndpointBuilder,
                uaaUserDatabase,
                jdbcClientDetailsService,
                keyInfoService
        );
    }

    @Bean("approvalStore")
    JdbcApprovalStore approvalStore() {
        return new JdbcApprovalStore(jdbcTemplate);
    }

    @Bean("idTokenGranter")
    IdTokenGranter idTokenGranter(@Qualifier("approvalService")ApprovalService approvalService) {
        return new IdTokenGranter(approvalService);
    }

    @Bean("approvalService")
    ApprovalService approvalService(@Qualifier("approvalStore") JdbcApprovalStore approvalStore) {
        return new ApprovalService(timeService, approvalStore, identityZoneManager);
    }

    @Bean("tokenServices")
    UaaTokenServices tokenServices(
            @Qualifier("idTokenCreator") IdTokenCreator idTokenCreator,
            @Qualifier("tokenEndpointBuilder") TokenEndpointBuilder tokenEndpointBuilder,
            @Qualifier("revocableTokenProvisioning") RevocableTokenProvisioning revocableTokenProvisioning,
            @Qualifier("tokenValidationService") TokenValidationService tokenValidationService,
            @Qualifier("refreshTokenCreator") RefreshTokenCreator refreshTokenCreator,
            @Qualifier("accessTokenValidityResolver") TokenValidityResolver accessTokenValidityResolver,
            @Qualifier("userDatabase") UaaUserDatabase userDatabase,
            @Qualifier("approvalService") ApprovalService approvalService,
            @Qualifier("excludedClaims") LinkedHashSet<String> excludedClaims,
            @Qualifier("globalTokenPolicy") TokenPolicy globalTokenPolicy,
            @Qualifier("keyInfoService") KeyInfoService keyInfoService,
            @Qualifier("idTokenGranter") IdTokenGranter idTokenGranter
    ) {
        return new UaaTokenServices(
                idTokenCreator,
                tokenEndpointBuilder,
                jdbcClientDetailsService,
                revocableTokenProvisioning,
                tokenValidationService,
                refreshTokenCreator,
                timeService,
                accessTokenValidityResolver,
                userDatabase,
                excludedClaims,
                globalTokenPolicy,
                keyInfoService,
                idTokenGranter,
                approvalService
        );
    }

    @Bean("uaaAuthenticationMgr")
    CheckIdpEnabledAuthenticationManager uaaAuthenticationMgr(
            @Qualifier("uaaUserDatabaseAuthenticationManager") AuthenticationManager delegate

    ) {
        return new CheckIdpEnabledAuthenticationManager(
                delegate,
                OriginKeys.UAA,
                providerProvisioning
        );
    }

    @Bean(value = "zoneAwareAuthzAuthenticationManager", destroyMethod = "destroy")
    DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager(
            CheckIdpEnabledAuthenticationManager uaaAuthenticationMgr,
            @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager externalMembershipManager,
            @Qualifier("scimGroupProvisioning")ScimGroupProvisioning scimGroupProvisioning,
            @Qualifier("ldapLoginAuthenticationMgr")LdapLoginAuthenticationManager ldapLoginAuthenticationManager
            ) {
        return new DynamicZoneAwareAuthenticationManager(
                providerProvisioning,
                uaaAuthenticationMgr,
                externalMembershipManager,
                scimGroupProvisioning,
                ldapLoginAuthenticationManager
        );
    }

    @Bean("oauthWithoutResourceAuthenticationFilter")
    FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> oauthWithoutResourceAuthenticationFilter(
            @Qualifier("tokenServices") UaaTokenServices tokenServices
    ) {
        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
        authenticationManager.setTokenServices(tokenServices);
        OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

}
