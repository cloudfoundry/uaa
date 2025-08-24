package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetailsSource;
import org.cloudfoundry.identity.uaa.authentication.UaaExceptionTranslator;
import org.cloudfoundry.identity.uaa.authentication.listener.AuthenticationSuccessListener;
import org.cloudfoundry.identity.uaa.authentication.manager.AutologinAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.LdapLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator;
import org.cloudfoundry.identity.uaa.client.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.YamlConfigurationValidator;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.provider.error.WebResponseExceptionTranslator;
import org.cloudfoundry.identity.uaa.oauth.provider.vote.ScopeVoter;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderWrapper;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.oauth.OauthIDPWrapperFactoryBean;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.ContextSensitiveOAuth2WebSecurityExpressionHandler;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.web.beans.UaaRequestRejectedHandler;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneAwareClientSecretPolicyValidator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.web.accept.ContentNegotiationManagerFactoryBean;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class SpringServletXmlBeansConfiguration {

    @Autowired
    IdentityZoneManager identityZoneManager;

    @Autowired
    @Qualifier("defaultUserAuthorities")
    Collection<String> defaultAuthorities;

    @Autowired
    UaaProperties.GlobalClientSecretPolicy globalClientSecretPolicy;

    @Autowired
    UaaProperties.DefaultClientSecretPolicy defaultClientSecretPolicy;

    @Autowired
    UaaProperties.Login loginProps;

    @Autowired
    UaaProperties.Logout logoutProps;

    @Bean
    YamlConfigurationValidator uaaConfigValidation(@Value("${environmentYamlKey}") String environmentYamlKey) {
        YamlConfigurationValidator bean = new YamlConfigurationValidator(new UaaConfiguration.UaaConfigConstructor());
        bean.setYaml(environmentYamlKey);
        return bean;
    }

    @Bean
    @Primary
    ContentNegotiationManagerFactoryBean contentNegotiationManager() {
        ContentNegotiationManagerFactoryBean bean = new ContentNegotiationManagerFactoryBean();
        bean.setFavorPathExtension(false);
        bean.setFavorParameter(true);
        bean.addMediaType("json", MediaType.APPLICATION_JSON);
        bean.addMediaType("xml", MediaType.APPLICATION_XML);
        bean.addMediaType("html", MediaType.TEXT_HTML);
        return bean;
    }

    @Bean
    RequestMappingHandlerMapping requestMappingHandlerMapping(
            @Qualifier("contentNegotiationManager") ContentNegotiationManagerFactoryBean contentNegotiationManagerFactoryBean
    ) {
        RequestMappingHandlerMapping bean = new RequestMappingHandlerMapping();
        bean.setContentNegotiationManager(contentNegotiationManagerFactoryBean.build());
        bean.setUseSuffixPatternMatch(false);
        bean.setOrder(1);
        return bean;
    }

    @Bean
    Boolean allowQueryStringForTokens(@Value("${jwt.token.queryString.enabled:true}") boolean enabled) {
        return enabled;
    }

    @Bean
    ChangeSessionIdAuthenticationStrategy sessionFixationProtectionStrategy() {
        return new ChangeSessionIdAuthenticationStrategy();
    }

    @Bean
    String uaaUrl(@Value("${uaa.url:http://localhost:8080/uaa}") String uaaUrl) {
        return uaaUrl;
    }

    @Bean
    String loginUrl(@Value("${login.url:http://localhost:8080/uaa}") String loginUrl) {
        return loginUrl;
    }

    @Bean
    ClientAdminEndpointsValidator clientDetailsValidator(
            SecurityContextAccessor securityContextAccessor,
            @Qualifier("clientDetailsService") QueryableResourceManager<ClientDetails> clientDetailsService,
            @Qualifier("zoneAwareClientSecretPolicyValidator") ClientSecretValidator clientDetailsValidator) {
        ClientAdminEndpointsValidator bean = new ClientAdminEndpointsValidator(securityContextAccessor, identityZoneManager);
        bean.setClientDetailsService(clientDetailsService);
        bean.setClientSecretValidator(clientDetailsValidator);
        return bean;

    }

    @Bean
    ClientAdminEventPublisher clientAdminEventPublisher(
            MultitenantClientServices clientDetailsService
    ) {
        return new ClientAdminEventPublisher(clientDetailsService, identityZoneManager);
    }

    @Bean
    ZoneAwareClientSecretPolicyValidator zoneAwareClientSecretPolicyValidator(
            @Qualifier("globalClientSecretPolicy") ClientSecretPolicy clientSecretPolicy
    ) {
        return new ZoneAwareClientSecretPolicyValidator(clientSecretPolicy);
    }

    @Bean
    ContextSensitiveOAuth2WebSecurityExpressionHandler oauthWebExpressionHandler() {
        return new ContextSensitiveOAuth2WebSecurityExpressionHandler();
    }

    @Bean
    ReloadableResourceBundleMessageSource messageSource() {
        String basenames = System.getenv().get("CLOUDFOUNDRY_CONFIG_PATH");
        if (basenames != null) {
            basenames = "file:" + basenames;
        } else {
            basenames = "classpath:messages";
        }
        ReloadableResourceBundleMessageSource bean = new ReloadableResourceBundleMessageSource();
        bean.setBasenames(basenames, "classpath:messages");
        return bean;
    }

    @Bean
    UaaAuthenticationDetailsSource authenticationDetailsSource() {
        return new UaaAuthenticationDetailsSource();
    }

    @Bean
    UaaExceptionTranslator accountNotVerifiedExceptionTranslator() {
        return new UaaExceptionTranslator();
    }

    @Bean
    OAuth2AuthenticationEntryPoint basicAuthenticationEntryPoint(
            @Qualifier("accountNotVerifiedExceptionTranslator") WebResponseExceptionTranslator<?> exceptionTranslator
    ) {
        OAuth2AuthenticationEntryPoint bean = new OAuth2AuthenticationEntryPoint();
        bean.setRealmName("UAA/client");
        bean.setTypeName("Basic");
        bean.setExceptionTranslator(exceptionTranslator);
        return bean;
    }

    @Bean
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {
        OAuth2AuthenticationEntryPoint bean = new OAuth2AuthenticationEntryPoint();
        bean.setRealmName("UAA/oauth");
        return bean;
    }

    @Bean
    UnanimousBased accessDecisionManager() {
        List<AccessDecisionVoter<?>> voters = new ArrayList<>();
        ScopeVoter scopeVoter = new ScopeVoter();
        scopeVoter.setScopePrefix("scope=");
        voters.add(scopeVoter);
        voters.add(new RoleVoter());
        voters.add(new AuthenticatedVoter());
        return new UnanimousBased(voters);
    }

    @Bean
    Http403ForbiddenEntryPoint http403EntryPoint() {
        return new Http403ForbiddenEntryPoint();
    }

    @Bean
    List<Prompt> prompts(
            @Value("${login.prompt.username.text:Email}") String username,
            @Value("${login.prompt.password.text:Password}") String password,
            @Value("${login.entityBaseURL:http://localhost:8080/uaa}") String passcode
    ) {
        return Arrays.asList(
                new Prompt("username", "text", username),
                new Prompt("password", "password", password),
                new Prompt("passcode", "password",
                        "Temporary Authentication Code ( Get one at " + passcode + "/passcode )")
        );
    }

    @Bean
    OidcMetadataFetcher oidcMetadataFetcher(
            UrlContentCache contentCache,
            @Qualifier("trustingRestTemplate") RestTemplate trustingRestTemplate,
            @Qualifier("nonTrustingRestTemplate") RestTemplate nonTrustingRestTemplate
    ) {
        return new OidcMetadataFetcher(contentCache, trustingRestTemplate, nonTrustingRestTemplate);
    }

    @Bean
    Links globalLinks(
            @Value("${links.global.passwd:#{null}}") String passwd,
            @Value("${links.global.signup:#{null}}") String signup,
            @Value("${links.global.homeRedirect:#{null}}") String homeRedirect
    ) {
        Links bean = new Links();
        Links.SelfService selfService = new Links.SelfService();
        selfService.setPasswd(passwd);
        selfService.setSignup(signup);
        bean.setSelfService(selfService);
        bean.setHomeRedirect(homeRedirect);
        return bean;
    }

    @Bean
    IdentityProviderBootstrap idpBootstrap(
            @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning,
            Environment environment,
            @Qualifier("defaultUaaPasswordPolicy") PasswordPolicy defaultUaaPasswordPolicy,
            @Qualifier("userLockoutPolicy") LockoutPolicy userLockoutPolicy,
            @Value("#{@config['disableInternalUserManagement'] == null ? false : @config['disableInternalUserManagement']}") boolean disableInternalUserManagement,
            @Value("#{@config['ldap']}") Map<String, Object> ldapConfig,
            @Qualifier("bootstrapMetaDataProviders") BootstrapSamlIdentityProviderData samlProviders,
            @Qualifier("oauthIdpDefinitions") List<IdentityProviderWrapper> oauthIdpDefinitions,
            @Value("#{@config['delete']==null ? null : @config['delete']['identityProviders']}") List<String> originsToDelete
    ) {
        IdentityProviderBootstrap bean = new IdentityProviderBootstrap(provisioning, identityZoneManager, environment);
        bean.setDefaultPasswordPolicy(defaultUaaPasswordPolicy);
        bean.setDefaultLockoutPolicy(userLockoutPolicy);
        bean.setDisableInternalUserManagement(disableInternalUserManagement);
        bean.setLdapConfig(ldapConfig);
        bean.setKeystoneConfig(null);
        bean.setSamlProviders(samlProviders);
        bean.setOauthIdpDefinitions(oauthIdpDefinitions);
        bean.setOriginsToDelete(originsToDelete);
        return bean;
    }

    @Bean
    OauthIDPWrapperFactoryBean oauthIdpConfigurator(
            @Value("#{@config['login']==null ? null : " +
                    "@config['login']['oauth']==null ? null : " +
                    "@config['login']['oauth']['providers']}") Map<String, Map> definitions
    ) {

        OauthIDPWrapperFactoryBean bean = new OauthIDPWrapperFactoryBean(definitions);
        return bean;
    }

    @Bean
    List<IdentityProviderWrapper> oauthIdpDefinitions(
            @Qualifier("oauthIdpConfigurator") OauthIDPWrapperFactoryBean oauthIdpConfigurator
    ) {
        return oauthIdpConfigurator.getProviders();
    }

    @Bean
    UserConfig defaultUserConfig(
            @Value("${login.allowedGroups:#{null}}") List<String> allowedGroups,
            @Value("${login.checkOriginEnabled:false}") boolean checkOriginEnabled,
            @Value("${login.maxUsers:-1}") int maxUsers,
            @Value("${login.allowOriginLoop:true}") boolean allowOriginLoop
    ) {
        UserConfig bean = new UserConfig();

        bean.setDefaultGroups(defaultAuthorities.stream().toList());
        bean.setAllowedGroups(allowedGroups);
        bean.setCheckOriginEnabled(checkOriginEnabled);
        bean.setMaxUsers(maxUsers);
        bean.setAllowOriginLoop(allowOriginLoop);
        return bean;
    }

    @Bean
    HashMap<String, Object> links(
            @Value("#{@config['links']==null ? T(java.util.Collections).EMPTY_MAP : @config['links']}") HashMap<String, Object> links
    ) {
        return links;
    }

    @Bean
    LdapLoginAuthenticationManager ldapLoginAuthenticationMgr(
            @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning,
            @Qualifier("userDatabase") JdbcUaaUserDatabase userDatabase
    ) {
        LdapLoginAuthenticationManager bean = new LdapLoginAuthenticationManager(provisioning);
        bean.setUserDatabase(userDatabase);
        bean.setOrigin(OriginKeys.LDAP);
        return bean;
    }

    @Bean
    AuthenticationSuccessListener authenticationSuccessListener(
            @Qualifier("scimUserProvisioning") JdbcScimUserProvisioning scimUserProvisioning
    ) {
        return new AuthenticationSuccessListener(scimUserProvisioning);
    }

    @Bean
    AutologinAuthenticationManager autologinAuthenticationManager(
            @Qualifier("codeStore") ExpiringCodeStore codeStore,
            @Qualifier("jdbcClientDetailsService") MultitenantClientServices jdbcClientDetailsService,
            @Qualifier("userDatabase") JdbcUaaUserDatabase userDatabase
    ) {
        AutologinAuthenticationManager bean = new AutologinAuthenticationManager();
        bean.setExpiringCodeStore(codeStore);
        bean.setClientDetailsService(jdbcClientDetailsService);
        bean.setUserDatabase(userDatabase);
        return bean;
    }

    @Bean
    ClientSecretPolicy globalClientSecretPolicy() {
        return new ClientSecretPolicy(
                globalClientSecretPolicy.minLength(),
                globalClientSecretPolicy.maxLength(),
                globalClientSecretPolicy.requireUpperCaseCharacter(),
                globalClientSecretPolicy.requireLowerCaseCharacter(),
                globalClientSecretPolicy.requireDigit(),
                globalClientSecretPolicy.requireSpecialCharacter(),
                globalClientSecretPolicy.expireSecretInMonths()
        );
    }

    @Bean
    ClientSecretPolicy defaultUaaClientSecretPolicy() {
        return new ClientSecretPolicy(
                defaultClientSecretPolicy.minLength(),
                defaultClientSecretPolicy.maxLength(),
                defaultClientSecretPolicy.requireUpperCaseCharacter(),
                defaultClientSecretPolicy.requireLowerCaseCharacter(),
                defaultClientSecretPolicy.requireDigit(),
                defaultClientSecretPolicy.requireSpecialCharacter(),
                defaultClientSecretPolicy.expireSecretInMonths()
        );
    }

    @Bean
    IdentityZoneConfigurationBootstrap identityZoneConfigurationBootstrap(
            IdentityZoneProvisioning provisioning,
            IdentityZoneValidator identityZoneValidator,
            @Qualifier("defaultUaaClientSecretPolicy") ClientSecretPolicy defaultUaaClientSecretPolicy,
            @Qualifier("uaaTokenPolicy") TokenPolicy uaaTokenPolicy,
            @Qualifier("links") HashMap<String, Object> links,
            @Qualifier("prompts") List<Prompt> prompts,
            @Qualifier("defaultUserConfig") UserConfig defaultUserConfig
    ) {
        IdentityZoneConfigurationBootstrap bean = new IdentityZoneConfigurationBootstrap(provisioning);
        bean.setValidator(identityZoneValidator);
        bean.setClientSecretPolicy(defaultUaaClientSecretPolicy);
        bean.setTokenPolicy(uaaTokenPolicy);
        bean.setSelfServiceLinksEnabled(loginProps.selfServiceLinksEnabled());
        bean.setSelfServiceLinks(links);
        if (links.containsKey("homeRedirect")) {
            bean.setHomeRedirect((String) links.get("homeRedirect"));
        } else {
            bean.setHomeRedirect(loginProps.homeRedirect());
        }
        bean.setIdpDiscoveryEnabled(loginProps.idpDiscoveryEnabled());
        bean.setAccountChooserEnabled(loginProps.accountChooserEnabled());
        bean.setLogoutRedirectWhitelist(logoutProps.redirect().parameter().whitelist());
        bean.setLogoutDefaultRedirectUrl(logoutProps.redirect().url());
        bean.setLogoutRedirectParameterName("redirect"); //hard coded in XML
        bean.setLogoutDisableRedirectParameter(logoutProps.redirect().parameter().disable());
        bean.setPrompts(prompts);
        bean.setBranding(loginProps.branding());
        bean.setSamlSpPrivateKey(loginProps.serviceProviderKey());
        bean.setSamlSpPrivateKeyPassphrase(loginProps.serviceProviderKeyPassword());
        bean.setSamlSpCertificate(loginProps.serviceProviderCertificate());
        bean.setActiveKeyId(loginProps.saml().activeKeyId());
        bean.setSamlKeys(loginProps.saml().keys());
        bean.setDisableSamlInResponseToCheck(loginProps.saml().disableInResponseToCheck());
        bean.setSamlWantAssertionSigned(loginProps.saml().wantAssertionSigned());
        bean.setSamlRequestSigned(loginProps.saml().signRequest());
        bean.setDefaultUserConfig(defaultUserConfig);
        bean.setDefaultIdentityProvider(loginProps.defaultIdentityProvider());
        return bean;
    }

    @Bean
    public RequestRejectedHandler requestRejectedHandler() {
        return new UaaRequestRejectedHandler();
    }
}
