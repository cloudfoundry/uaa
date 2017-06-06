/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.account.ResetPasswordController;
import org.cloudfoundry.identity.uaa.audit.JdbcFailedLoginCountingAuditService;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.NotificationsService;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenStore;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGenerator;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.web.HeaderFilter;
import org.cloudfoundry.identity.uaa.web.UaaSessionCookieConfig;
import org.cloudfoundry.identity.uaa.zone.*;
import org.flywaydb.core.Flyway;
import org.junit.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import javax.servlet.RequestDispatcher;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.*;
import static org.springframework.http.HttpHeaders.*;

public class BootstrapTests {

    private ConfigurableApplicationContext context;

    private static String systemConfiguredProfiles;
    private String profiles;
    private static volatile boolean initialized;

    @BeforeClass
    public static void saveProfiles() {
        systemConfiguredProfiles = System.getProperty("spring.profiles.active");
        initialized = false;
    }

    @AfterClass
    public static void restoreProfiles() {
        if (systemConfiguredProfiles != null) {
            System.setProperty("spring.profiles.active", systemConfiguredProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

    @Before
    public synchronized void setup() throws Exception {
        System.clearProperty("spring.profiles.active");
        IdentityZoneHolder.clear();
        profiles = systemConfiguredProfiles==null ? "default,hsqldb" : (systemConfiguredProfiles != null && systemConfiguredProfiles.contains("default")) ? systemConfiguredProfiles : systemConfiguredProfiles+",default";
        if (!initialized) {
            getServletContext(profiles +",default", false, new String[] {"login.yml", "uaa.yml", "required_configuration.yml"}, true, "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            initialized = true;
        }
    }

    @After
    public synchronized void cleanup() throws Exception {
        System.clearProperty("spring.profiles.active");
        System.clearProperty("uaa.url");
        System.clearProperty("login.url");
        System.clearProperty("require_https");
        if (context != null) {
            context.close();
        }
        Set<String> removeme = new HashSet<>();
        for ( Map.Entry<Object,Object> entry : System.getProperties().entrySet()) {
            if (entry.getKey().toString().startsWith("login.") || entry.getKey().toString().startsWith("database.")) {
                removeme.add(entry.getKey().toString());
            }
        }
        for (String s : removeme) {
            System.clearProperty(s);
        }
        IdentityZoneHolder.clear();
    }

    @Test
    public void testNoDefaultProfileIsLoaded() throws Exception {
        System.clearProperty("spring.profiles.active");
        context = getServletContext(null, false, new String[] {"login.yml", "test/bootstrap/uaa.yml", "required_configuration.yml"}, "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        String[] profiles = context.getEnvironment().getActiveProfiles();
        assertThat("'default' profile should not be loaded", profiles, not(hasItemInArray("default")));
        profiles = context.getEnvironment().getDefaultProfiles();
        assertThat("'default' profile should not be default", profiles, not(hasItemInArray("default")));
    }

    @Test
    public void testRootContextDefaults() throws Exception {
        String originalSmtpHost = System.getProperty("smtp.host");
        System.setProperty("smtp.host","");

        context = getServletContext(profiles +",default", false, new String[] {"login.yml", "uaa.yml", "required_configuration.yml"}, "file:./src/main/webapp/WEB-INF/spring-servlet.xml");

        HeaderFilter filterWrapper = context.getBean(HeaderFilter.class);
        assertNotNull(filterWrapper);
        assertThat(
            Arrays.asList("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Prefix", "Forwarded"),
            containsInAnyOrder(filterWrapper.getFilteredHeaderNames().toArray())
        );

        JdbcFailedLoginCountingAuditService auditService = context.getBean(JdbcFailedLoginCountingAuditService.class);
        assertFalse(auditService.isClientEnabled());

        JdbcUaaUserDatabase userDatabase = context.getBean(JdbcUaaUserDatabase.class);
        if (profiles != null && profiles.contains("mysql")) {
            assertTrue(userDatabase.isCaseInsensitive());
            assertEquals("marissa", userDatabase.retrieveUserByName("marissa", OriginKeys.UAA).getUsername());
            assertEquals("marissa", userDatabase.retrieveUserByName("MArissA", OriginKeys.UAA).getUsername());
        } else {
            assertFalse(userDatabase.isCaseInsensitive());
        }

        assertNotNull(context.getBean("identityZoneHolderInitializer"));

        assertEquals(300, context.getBean(CachingPasswordEncoder.class).getExpiryInSeconds());
        assertEquals(true, context.getBean(CachingPasswordEncoder.class).isEnabled());

        UaaSessionCookieConfig sessionCookieConfig = context.getBean(UaaSessionCookieConfig.class);
        assertNotNull(sessionCookieConfig);
        assertNull(sessionCookieConfig.getComment());
        assertNull(sessionCookieConfig.getDomain());
        assertNull(sessionCookieConfig.getPath());
        assertNull(sessionCookieConfig.getName());
        assertEquals(Integer.MIN_VALUE, sessionCookieConfig.getMaxAge());
        assertTrue(sessionCookieConfig.isHttpOnly());
        assertFalse(sessionCookieConfig.isSecure());

        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        assertEquals(864000, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
        IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
        Set<String> defaultHostnames = new HashSet<>(Arrays.asList("localhost"));
        assertEquals(filter.getDefaultZoneHostnames(), defaultHostnames);

        assertSame(UaaTokenStore.class, context.getBean(AuthorizationCodeServices.class).getClass());

        IdentityZoneProvisioning zoneProvisioning = context.getBean(IdentityZoneProvisioning.class);
        IdentityZoneConfiguration zoneConfiguration = zoneProvisioning.retrieve(IdentityZone.getUaa().getId()).getConfig();
        assertTrue(zoneConfiguration.getLinks().getSelfService().isSelfServiceLinksEnabled());
        assertNull(zoneConfiguration.getLinks().getHomeRedirect());
        assertEquals("redirect", zoneConfiguration.getLinks().getLogout().getRedirectParameterName());
        assertEquals("/login", zoneConfiguration.getLinks().getLogout().getRedirectUrl());
        assertNull(zoneConfiguration.getLinks().getLogout().getWhitelist());
        assertFalse(zoneConfiguration.getLinks().getLogout().isDisableRedirectParameter());
        assertFalse(context.getBean(IdentityZoneProvisioning.class).retrieve(IdentityZone.getUaa().getId()).getConfig().getTokenPolicy().isJwtRevocable());
        assertEquals(
            Arrays.asList(
                new Prompt("username", "text", "Email"),
                new Prompt("password", "password", "Password"),
                new Prompt("passcode", "password", "One Time Code ( Get one at http://localhost:8080/uaa/passcode )")
            ),
            zoneConfiguration.getPrompts()
        );

        Object links = context.getBean("links");
        assertEquals(Collections.EMPTY_MAP, links);

        //check java mail sender
        EmailService emailService = context.getBean("emailService", EmailService.class);
        Field f = ReflectionUtils.findField(EmailService.class, "mailSender");
        assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", f);
        assertEquals(FakeJavaMailSender.class, emailService.getMailSender().getClass());

        assertEquals("admin@localhost", emailService.getFromAddress());

        PasswordPolicy passwordPolicy = context.getBean("defaultUaaPasswordPolicy",PasswordPolicy.class);
        assertEquals(0, passwordPolicy.getMinLength());
        assertEquals(255, passwordPolicy.getMaxLength());
        assertEquals(0,passwordPolicy.getRequireUpperCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireLowerCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireDigit());
        assertEquals(0,passwordPolicy.getRequireSpecialCharacter());
        assertEquals(0, passwordPolicy.getExpirePasswordInMonths());

        passwordPolicy = context.getBean("globalPasswordPolicy",PasswordPolicy.class);
        assertEquals(0, passwordPolicy.getMinLength());
        assertEquals(255, passwordPolicy.getMaxLength());
        assertEquals(0,passwordPolicy.getRequireUpperCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireLowerCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireDigit());
        assertEquals(0,passwordPolicy.getRequireSpecialCharacter());
        assertEquals(0, passwordPolicy.getExpirePasswordInMonths());

        PeriodLockoutPolicy globalPeriodLockoutPolicy = context.getBean("globalPeriodLockoutPolicy", PeriodLockoutPolicy.class);
        LockoutPolicy globalLockoutPolicy = globalPeriodLockoutPolicy.getDefaultLockoutPolicy();
        Assert.assertThat(globalLockoutPolicy.getLockoutAfterFailures(), equalTo(5));
        Assert.assertThat(globalLockoutPolicy.getCountFailuresWithin(), equalTo(1200));
        Assert.assertThat(globalLockoutPolicy.getLockoutPeriodSeconds(), equalTo(300));

        TokenPolicy tokenPolicy = context.getBean("uaaTokenPolicy",TokenPolicy.class);
        Assert.assertThat(tokenPolicy.getAccessTokenValidity(), equalTo(60 * 60 * 12));
        Assert.assertThat(tokenPolicy.getRefreshTokenValidity(), equalTo(60 * 60 * 24 * 30));

        UaaTokenServices uaaTokenServices = context.getBean("tokenServices",UaaTokenServices.class);
        Assert.assertThat(uaaTokenServices.getTokenPolicy().getAccessTokenValidity(), equalTo(60 * 60 * 12));
        Assert.assertThat(uaaTokenServices.getTokenPolicy().getRefreshTokenValidity(), equalTo(60 * 60 * 24 * 30));

        List<Prompt> prompts = (List<Prompt>) context.getBean("prompts");
        assertNotNull(prompts);
        assertEquals(3, prompts.size());
        Prompt passcode = prompts.get(0);
        assertEquals("Email", passcode.getDetails()[1]);
        passcode = prompts.get(1);
        assertEquals("Password",passcode.getDetails()[1]);
        passcode = prompts.get(2);
        assertEquals("One Time Code ( Get one at http://localhost:8080/uaa/passcode )", passcode.getDetails()[1]);

        ZoneAwareMetadataGenerator zoneAwareMetadataGenerator = context.getBean(ZoneAwareMetadataGenerator.class);
        assertTrue(zoneAwareMetadataGenerator.isRequestSigned());
        assertTrue(zoneAwareMetadataGenerator.isWantAssertionSigned());

        CorsFilter corFilter = context.getBean(CorsFilter.class);

        assertEquals(1728000, corFilter.getXhrConfiguration().getMaxAge());
        assertEquals(1728000, corFilter.getDefaultConfiguration().getMaxAge());

        assertEquals(1, corFilter.getXhrConfiguration().getAllowedUris().size());
        assertEquals(".*", corFilter.getXhrConfiguration().getAllowedUris().get(0));
        assertEquals(1, corFilter.getXhrConfiguration().getAllowedUris().size());
        assertEquals(".*", corFilter.getDefaultConfiguration().getAllowedUris().get(0));
        assertEquals(1, corFilter.getXhrConfiguration().getAllowedUriPatterns().size());
        assertEquals(1, corFilter.getDefaultConfiguration().getAllowedUriPatterns().size());

        assertThat(corFilter.getXhrConfiguration().getAllowedHeaders(), containsInAnyOrder(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE,AUTHORIZATION, CorsFilter.X_REQUESTED_WITH));
        assertThat(corFilter.getDefaultConfiguration().getAllowedHeaders(), containsInAnyOrder(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE,AUTHORIZATION));

        assertThat(corFilter.getXhrConfiguration().getAllowedOrigins(), containsInAnyOrder(".*"));
        assertThat(corFilter.getDefaultConfiguration().getAllowedOrigins(), containsInAnyOrder(".*"));

        assertThat(corFilter.getXhrConfiguration().getAllowedMethods(), containsInAnyOrder("OPTIONS", "GET"));
        assertThat(corFilter.getDefaultConfiguration().getAllowedMethods(), containsInAnyOrder("OPTIONS", "GET", "POST", "PUT", "DELETE", "PATCH"));

        assertTrue(corFilter.getXhrConfiguration().isAllowedCredentials());
        assertFalse(corFilter.getDefaultConfiguration().isAllowedCredentials());

        if (StringUtils.hasText(originalSmtpHost)) {
            System.setProperty("smtp.host", originalSmtpHost);
        } else {
            System.clearProperty("smtp.host");
        }

        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, Configuration.getGlobalSecurityConfiguration().getSignatureAlgorithmURI("RSA"));
        assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA1, Configuration.getGlobalSecurityConfiguration().getSignatureReferenceDigestMethod());

    }

    @Test
    public void testPropertyValuesWhenSetInYaml() throws Exception {
        String uaa = "uaa.some.test.domain.com";
        String login = uaa.replace("uaa", "login");
        String profiles = System.getProperty("spring.profiles.active");
        context = getServletContext(profiles, false, new String[] {"login.yml", "uaa.yml", "required_configuration.yml", "test/bootstrap/bootstrap-test.yml"}, "file:./src/main/webapp/WEB-INF/spring-servlet.xml");

        HeaderFilter filterWrapper = context.getBean(HeaderFilter.class);
        assertNotNull(filterWrapper);
        assertThat(
            Arrays.asList("X-Forwarded-Host", "Forwarded"),
            containsInAnyOrder(filterWrapper.getFilteredHeaderNames().toArray())
        );

        JdbcFailedLoginCountingAuditService auditService = context.getBean(JdbcFailedLoginCountingAuditService.class);
        assertTrue(auditService.isClientEnabled());


        JdbcUaaUserDatabase userDatabase = context.getBean(JdbcUaaUserDatabase.class);
        assertTrue(userDatabase.isCaseInsensitive());


        assertEquals(600, context.getBean(CachingPasswordEncoder.class).getExpiryInSeconds());
        assertEquals(false, context.getBean(CachingPasswordEncoder.class).isEnabled());

        UaaSessionCookieConfig sessionCookieConfig = context.getBean(UaaSessionCookieConfig.class);
        assertNotNull(sessionCookieConfig);
        assertEquals("C is for Cookie", sessionCookieConfig.getComment());
        assertEquals("sesame.com", sessionCookieConfig.getDomain());
        assertEquals("/the/path/to/the/jar", sessionCookieConfig.getPath());
        assertEquals("cookiemonster", sessionCookieConfig.getName());
        assertEquals(30, sessionCookieConfig.getMaxAge());
        assertFalse(sessionCookieConfig.isHttpOnly());
        assertTrue(sessionCookieConfig.isSecure());

        IdentityZoneProvisioning zoneProvisioning = context.getBean(IdentityZoneProvisioning.class);
        IdentityZoneConfiguration zoneConfiguration = zoneProvisioning.retrieve(IdentityZone.getUaa().getId()).getConfig();
        assertFalse(zoneConfiguration.getLinks().getSelfService().isSelfServiceLinksEnabled());
        assertEquals("http://some.redirect.com/redirect", zoneConfiguration.getLinks().getHomeRedirect());
        assertEquals("/configured_signup", zoneConfiguration.getLinks().getSelfService().getSignup());
        assertEquals("/configured_passwd", zoneConfiguration.getLinks().getSelfService().getPasswd());

        assertEquals("redirect", zoneConfiguration.getLinks().getLogout().getRedirectParameterName());
        assertEquals("/configured_login", zoneConfiguration.getLinks().getLogout().getRedirectUrl());
        assertEquals(Arrays.asList("https://url1.domain1.com/logout-success","https://url2.domain2.com/logout-success"), zoneConfiguration.getLinks().getLogout().getWhitelist());
        assertTrue(zoneConfiguration.getLinks().getLogout().isDisableRedirectParameter());

        assertEquals(SamlLoginServerKeyManagerTests.CERTIFICATE.trim(), zoneConfiguration.getSamlConfig().getCertificate().trim());
        assertEquals(SamlLoginServerKeyManagerTests.KEY.trim(), zoneConfiguration.getSamlConfig().getPrivateKey().trim());
        assertEquals(SamlLoginServerKeyManagerTests.PASSWORD.trim(), zoneConfiguration.getSamlConfig().getPrivateKeyPassword().trim());

        assertTrue(context.getBean(IdentityZoneProvisioning.class).retrieve(IdentityZone.getUaa().getId()).getConfig().getTokenPolicy().isJwtRevocable());
        ZoneAwareMetadataGenerator zoneAwareMetadataGenerator = context.getBean(ZoneAwareMetadataGenerator.class);
        assertFalse(zoneAwareMetadataGenerator.isWantAssertionSigned());

        assertEquals(
            Arrays.asList(
                new Prompt("username", "text", "Username"),
                new Prompt("password", "password", "Your Secret"),
                new Prompt("passcode", "password", "One Time Code ( Get one at https://login.some.test.domain.com:555/uaa/passcode )")
            ),
            zoneConfiguration.getPrompts()
        );

        IdentityProviderProvisioning idpProvisioning = context.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = idpProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        assertTrue(uaaIdp.getConfig().isDisableInternalUserManagement());
        assertFalse(uaaIdp.isActive());

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcProvider = idpProvisioning.retrieveByOrigin("my-oidc-provider", IdentityZone.getUaa().getId());
        assertNotNull(oidcProvider);
        assertEquals("http://my-auth.com", oidcProvider.getConfig().getAuthUrl().toString());
        assertEquals("http://my-token.com", oidcProvider.getConfig().getTokenUrl().toString());
        assertNull(oidcProvider.getConfig().getIssuer());
        assertEquals("my-token-key", oidcProvider.getConfig().getTokenKey());
        assertEquals(true, oidcProvider.getConfig().isShowLinkText());
        assertEquals("uaa", oidcProvider.getConfig().getRelyingPartyId());
        assertEquals("secret", oidcProvider.getConfig().getRelyingPartySecret());
        assertEquals("my-oidc-provider", oidcProvider.getOriginKey());
        assertEquals("first_name", oidcProvider.getConfig().getAttributeMappings().get(GIVEN_NAME_ATTRIBUTE_NAME));
        assertEquals("last_name", oidcProvider.getConfig().getAttributeMappings().get(FAMILY_NAME_ATTRIBUTE_NAME));
        assertTrue(oidcProvider.getConfig().isAddShadowUserOnLogin());
        assertEquals(OIDC10, oidcProvider.getType());
        assertEquals(Collections.singletonList("requested_scope"), oidcProvider.getConfig().getScopes());
        assertEquals("code id_token", oidcProvider.getConfig().getResponseType());

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oauthProvider = idpProvisioning.retrieveByOrigin("my-oauth-provider", IdentityZone.getUaa().getId());
        assertNotNull(oauthProvider);
        assertEquals("http://my-auth.com", oauthProvider.getConfig().getAuthUrl().toString());
        assertEquals("http://my-token.com", oauthProvider.getConfig().getTokenUrl().toString());
        assertEquals("http://issuer-my-token.com", oauthProvider.getConfig().getIssuer());
        assertEquals("my-token-key", oauthProvider.getConfig().getTokenKey());
        assertEquals(true, oauthProvider.getConfig().isShowLinkText());
        assertEquals("uaa", oauthProvider.getConfig().getRelyingPartyId());
        assertEquals("secret", oauthProvider.getConfig().getRelyingPartySecret());
        assertEquals("my-oauth-provider", oauthProvider.getOriginKey());
        assertEquals("first_name", oauthProvider.getConfig().getAttributeMappings().get(GIVEN_NAME_ATTRIBUTE_NAME));
        assertEquals("last_name", oauthProvider.getConfig().getAttributeMappings().get(FAMILY_NAME_ATTRIBUTE_NAME));
        assertFalse(oauthProvider.getConfig().isAddShadowUserOnLogin());
        assertEquals(OAUTH20, oauthProvider.getType());
        assertEquals(Collections.singletonList("requested_scope"), oauthProvider.getConfig().getScopes());
        assertEquals(Collections.singletonList("example.com"), oauthProvider.getConfig().getEmailDomain());
        assertEquals("code", oauthProvider.getConfig().getResponseType());

        IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
        assertThat(filter.getDefaultZoneHostnames(), containsInAnyOrder(uaa, login, "localhost", "host1.domain.com", "host2", "test3.localhost", "test4.localhost"));
        DataSource ds = context.getBean(DataSource.class);
        assertEquals(50, ds.getMaxActive());
        assertEquals(3, ds.getMinIdle());
        assertEquals(5, ds.getMaxIdle());
        assertTrue(ds.isRemoveAbandoned());
        assertFalse(ds.isLogAbandoned());
        assertEquals(45, ds.getRemoveAbandonedTimeout());
        assertEquals(30000, ds.getTimeBetweenEvictionRunsMillis());
        assertTrue(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
        //check java mail sender
        EmailService emailService = context.getBean("emailService", EmailService.class);
        assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", emailService.getMailSender());
        assertEquals(JavaMailSenderImpl.class, emailService.getMailSender().getClass());
        JavaMailSenderImpl mailSender = (JavaMailSenderImpl) emailService.getMailSender();
        Properties mailProperties = mailSender.getJavaMailProperties();
        assertEquals("true", mailProperties.getProperty("mail.smtp.auth"));
        assertEquals("true", mailProperties.getProperty("mail.smtp.starttls.enable"));
        assertEquals("test@example.com", emailService.getFromAddress());

        PasswordPolicy passwordPolicy = context.getBean("defaultUaaPasswordPolicy",PasswordPolicy.class);
        assertEquals(8, passwordPolicy.getMinLength());
        assertEquals(100, passwordPolicy.getMaxLength());
        assertEquals(0,passwordPolicy.getRequireUpperCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireLowerCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireDigit());
        assertEquals(1,passwordPolicy.getRequireSpecialCharacter());
        assertEquals(6, passwordPolicy.getExpirePasswordInMonths());

        context.getBean("globalPasswordPolicy", PasswordPolicy.class);
        assertEquals(8, passwordPolicy.getMinLength());
        assertEquals(100, passwordPolicy.getMaxLength());
        assertEquals(0,passwordPolicy.getRequireUpperCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireLowerCaseCharacter());
        assertEquals(0,passwordPolicy.getRequireDigit());
        assertEquals(1,passwordPolicy.getRequireSpecialCharacter());
        assertEquals(6, passwordPolicy.getExpirePasswordInMonths());

        PeriodLockoutPolicy globalPeriodLockoutPolicy = context.getBean("globalPeriodLockoutPolicy", PeriodLockoutPolicy.class);
        LockoutPolicy globalLockoutPolicy = globalPeriodLockoutPolicy.getDefaultLockoutPolicy();
        Assert.assertThat(globalLockoutPolicy.getLockoutAfterFailures(), equalTo(1));
        Assert.assertThat(globalLockoutPolicy.getCountFailuresWithin(), equalTo(2222));
        Assert.assertThat(globalLockoutPolicy.getLockoutPeriodSeconds(), equalTo(152));

        AuthzAuthenticationManager manager = (AuthzAuthenticationManager) context.getBean("uaaUserDatabaseAuthenticationManager");
        PeriodLockoutPolicy accountLoginPolicy = (PeriodLockoutPolicy) manager.getAccountLoginPolicy();
        assertEquals(2222, accountLoginPolicy.getDefaultLockoutPolicy().getCountFailuresWithin());
        assertEquals(152, accountLoginPolicy.getDefaultLockoutPolicy().getLockoutPeriodSeconds());
        assertEquals(1, accountLoginPolicy.getDefaultLockoutPolicy().getLockoutAfterFailures());

        UaaTokenServices uaaTokenServices = context.getBean("tokenServices",UaaTokenServices.class);
        Assert.assertThat(uaaTokenServices.getTokenPolicy().getAccessTokenValidity(), equalTo(3600));
        Assert.assertThat(uaaTokenServices.getTokenPolicy().getRefreshTokenValidity(), equalTo(7200));

        TokenPolicy tokenPolicy = context.getBean("uaaTokenPolicy",TokenPolicy.class);
        Assert.assertThat(tokenPolicy.getAccessTokenValidity(), equalTo(4800));
        Assert.assertThat(tokenPolicy.getRefreshTokenValidity(), equalTo(9600));

        List<Prompt> prompts = (List<Prompt>) context.getBean("prompts");
        assertNotNull(prompts);
        assertEquals(3, prompts.size());
        Prompt passcode = prompts.get(0);
        assertEquals("Username", passcode.getDetails()[1]);
        passcode = prompts.get(1);
        assertEquals("Your Secret", passcode.getDetails()[1]);
        passcode = prompts.get(2);
        assertEquals("One Time Code ( Get one at https://login.some.test.domain.com:555/uaa/passcode )", passcode.getDetails()[1]);

        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, Configuration.getGlobalSecurityConfiguration().getSignatureAlgorithmURI("RSA"));
        assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA256, Configuration.getGlobalSecurityConfiguration().getSignatureReferenceDigestMethod());
    }

    @Test
    public void testDefaultInternalHostnamesAndNoDBSettings_and_Cookie_isSecure() throws Exception {
        try {
            //testing to see if session cookie config confirms to this
            System.setProperty("require_https","true");


            System.setProperty("smtp.host","localhost");
            //travis profile script overrides these properties
            System.setProperty("database.maxactive", "100");
            System.setProperty("database.maxidle", "10");
            System.setProperty("database.minidle", "5");
            String uaa = "uaa.some.test.domain.com";
            String login = uaa.replace("uaa", "login");
            System.setProperty("uaa.url", "https://" + uaa + ":555/uaa");
            System.setProperty("login.url", "https://" + login + ":555/uaa");
            context = getServletContext(null, "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");

            UaaSessionCookieConfig sessionCookieConfig = context.getBean(UaaSessionCookieConfig.class);
            assertNotNull(sessionCookieConfig);
            assertTrue(sessionCookieConfig.isSecure());


            IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
            Set<String> defaultHostnames = new HashSet<>(Arrays.asList(uaa, login, "localhost"));
            assertEquals(filter.getDefaultZoneHostnames(), defaultHostnames);
            DataSource ds = context.getBean(DataSource.class);
            assertEquals(100, ds.getMaxActive());
            assertEquals(10, ds.getMaxIdle());
            assertEquals(5, ds.getMinIdle());
            assertFalse(ds.isRemoveAbandoned());
            assertTrue(ds.isLogAbandoned());
            assertEquals(300, ds.getRemoveAbandonedTimeout());
            assertEquals(15000, ds.getTimeBetweenEvictionRunsMillis());
            if ("mysql".equals(context.getBean("platform"))) {
                assertTrue(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
            } else {
                assertFalse(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
            }
            //check java mail sender
            EmailService emailService = context.getBean("emailService", EmailService.class);
            assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", emailService.getMailSender());
            assertEquals(JavaMailSenderImpl.class, emailService.getMailSender().getClass());

            assertEquals("admin@" + login, emailService.getFromAddress());

        } finally {
            System.clearProperty("database.maxactive");
            System.clearProperty("database.maxidle");
            System.clearProperty("database.minidle");
            System.clearProperty("smtp.host");
            System.clearProperty("uaa.url");
            System.clearProperty("login.url");
        }
    }

    @Test
    public void bootstrap_commaSeparated_scim_groups_from_yaml() throws Exception {
        context = getServletContext(null, "login.yml", "test/bootstrap/uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll();
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));
    }

    @Test
    public void bootstrap_scim_groups_asMap_from_yaml() throws Exception {
        context = getServletContext(null, "login.yml", "test/bootstrap/config_with_groups.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll();
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));
    }

    @Test(expected = BeanCreationException.class)
    public void invalid_saml_signature_algorithm() throws Exception {
        context = getServletContext(null, "login.yml", "test/bootstrap/config_with_invalid_saml_signature_algorithm.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
    }

    @Test
    public void bootstrap_idpDiscoveryEnabled_from_yml() throws Exception {
        context = getServletContext(null, "login.yml", "test/bootstrap/bootstrap-test.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        IdentityZoneConfigurationBootstrap bean = context.getBean(IdentityZoneConfigurationBootstrap.class);
        assertTrue(bean.isIdpDiscoveryEnabled());
    }

    @Test
    public void bootstrap_branding_from_yml() throws Exception {
        context = getServletContext(null, "login.yml", "test/bootstrap/bootstrap-test.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        IdentityZoneConfigurationBootstrap bean = context.getBean(IdentityZoneConfigurationBootstrap.class);

        assertNotNull(bean.getBranding());
        assertEquals(bean.getBranding().get("companyName"), "test-company-branding-name");
        assertThat((String) bean.getBranding().get("squareLogo"), containsString("this is an invalid"));
        assertThat((String) bean.getBranding().get("productLogo"), containsString("base64 logo with"));
    }

    @Test
    public void testBootstrappedIdps_and_ExcludedClaims_and_CorsConfig() throws Exception {

        //generate login.yml with SAML and uaa.yml with LDAP
        System.setProperty("database.caseinsensitive", "false");
        context = getServletContext("ldap,default", true, "test/bootstrap/login.yml,login.yml","test/bootstrap/uaa.yml,uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        BootstrapSamlIdentityProviderConfigurator samlProviders = context.getBean(BootstrapSamlIdentityProviderConfigurator.class);
        IdentityProviderProvisioning providerProvisioning = context.getBean("identityProviderProvisioning", IdentityProviderProvisioning.class);
        //ensure that ldap has been loaded up
        assertFalse(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
        //ensure we have some saml providers in login.yml
        //we have provided 4 here, but the original login.yml may add, but not remove some
        assertTrue(samlProviders.getIdentityProviderDefinitions().size() >= 4);

        assertThat(context.getBean(UaaTokenServices.class).getExcludedClaims(), containsInAnyOrder(ClaimConstants.AUTHORITIES));

        //verify that they got loaded in the DB
        for (SamlIdentityProviderDefinition def : samlProviders.getIdentityProviderDefinitions()) {
            assertNotNull(providerProvisioning.retrieveByOrigin(def.getIdpEntityAlias(), IdentityZone.getUaa().getId()));
        }

        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider =
            providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZone.getUaa().getId());
        assertNotNull(ldapProvider);
        assertFalse(ldapProvider.getConfig().isAddShadowUserOnLogin());
        assertEquals("Test LDAP Provider Description", ldapProvider.getConfig().getProviderDescription());

        IdentityProvider<SamlIdentityProviderDefinition> samlProvider = providerProvisioning.retrieveByOrigin("okta-local", IdentityZone.getUaa().getId());
        assertEquals("Test Okta Preview 1 Description", samlProvider.getConfig().getProviderDescription());
        assertEquals(SamlIdentityProviderDefinition.ExternalGroupMappingMode.EXPLICITLY_MAPPED, samlProvider.getConfig().getGroupMappingMode());
        assertTrue(samlProvider.getConfig().isSkipSslValidation());

        IdentityProvider<SamlIdentityProviderDefinition> samlProvider2 = providerProvisioning.retrieveByOrigin("okta-local-2", IdentityZone.getUaa().getId());
        assertEquals(SamlIdentityProviderDefinition.ExternalGroupMappingMode.AS_SCOPES, samlProvider2.getConfig().getGroupMappingMode());
        assertFalse(samlProvider2.getConfig().isSkipSslValidation());

        IdentityProvider<SamlIdentityProviderDefinition> samlProvider3 = providerProvisioning.retrieveByOrigin("vsphere.local", IdentityZone.getUaa().getId());
        assertTrue(samlProvider3.getConfig().isSkipSslValidation());

        CorsFilter filter = context.getBean(CorsFilter.class);

        for (CorsConfiguration configuration : Arrays.asList(filter.getXhrConfiguration(), filter.getDefaultConfiguration())) {
            assertEquals(1999999, configuration.getMaxAge());
            assertEquals(1, configuration.getAllowedUris().size());
            assertEquals(".*token$", configuration.getAllowedUris().get(0));
            assertEquals(1, configuration.getAllowedUriPatterns().size());
            assertTrue(configuration.isAllowedCredentials());
            assertThat(configuration.getAllowedHeaders(), containsInAnyOrder("Accept", "Content-Type"));
            assertThat(configuration.getAllowedOrigins(), containsInAnyOrder("^example.com.*", "foo.com"));
            assertThat(configuration.getAllowedMethods(), containsInAnyOrder("PUT", "POST", "GET"));
        }
    }

    @Test
    public void bootstrap_map_of_signing_and_verification_keys_in_default_zone() throws NoSuchAlgorithmException {
        context = getServletContext("ldap,default", true, "test/bootstrap/login.yml,login.yml", "test/bootstrap/uaa.yml,uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        TokenPolicy uaaTokenPolicy = context.getBean("uaaTokenPolicy", TokenPolicy.class);
        assertThat(uaaTokenPolicy, is(notNullValue()));
        assertThat(uaaTokenPolicy.getKeys().size(), comparesEqualTo(2));
        assertEquals(false, uaaTokenPolicy.isRefreshTokenUnique());
        assertEquals(JWT.getStringValue(), uaaTokenPolicy.getRefreshTokenFormat());
        Map<String, String> keys = uaaTokenPolicy.getKeys();
        assertTrue(keys.keySet().contains("key-id-1"));
        String signingKey = keys.get("key-id-1");
        assertThat(signingKey, containsString("test-signing-key"));
        assertThat(uaaTokenPolicy.getActiveKeyId(), is("key-id-2"));
    }

    @Test
    public void test_bootstrap_of_token_policy() {
        context = getServletContext(null, "login.yml", "test/bootstrap/bootstrap-test.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        TokenPolicy uaaTokenPolicy = context.getBean("uaaTokenPolicy", TokenPolicy.class);
        assertEquals(true, uaaTokenPolicy.isRefreshTokenUnique());
        assertEquals(OPAQUE.getStringValue(), uaaTokenPolicy.getRefreshTokenFormat());
    }

    @Test
    public void testSamlProfileNoData() throws Exception {
        System.setProperty("login.saml.maxAuthenticationAge", "3600");
        System.setProperty("login.saml.metadataTrustCheck", "false");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertEquals(3600, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
        Assume.assumeTrue(context.getEnvironment().getProperty("login.idpMetadataURL") == null);
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(0, context.getBean(BootstrapSamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions().size());
    }

    @Test
    public void testLegacySamlHttpMetaUrl() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.uaa-acceptance.cf-app.com/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPFile");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertNotNull(findProvider(defs, "testIDPFile"));
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.URL,
            findProvider(defs, "testIDPFile").getType());
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.URL,
            defs.get(defs.size() - 1).getType()
        );
    }

    protected SamlIdentityProviderDefinition findProvider(List<SamlIdentityProviderDefinition> defs, String alias) {
        for (SamlIdentityProviderDefinition def : defs) {
            if (alias.equals(def.getIdpEntityAlias())) {
                return def;
            }
        }
        return null;
    }

    @Test
    public void testLegacySamlProfileMetadataConfig() throws Exception {
        String metadataString = new Scanner(new File("./src/main/resources/sample-okta-localhost.xml")).useDelimiter("\\Z").next();
        System.setProperty("login.idpMetadata", metadataString);
        System.setProperty("login.idpEntityAlias", "testIDPData");
        context = getServletContext("default,saml,configMetadata", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.DATA,
            findProvider(defs, "testIDPData").getType());
    }


    @Test
    public void testLegacySamlProfileHttpsMetaUrl() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.uaa-acceptance.cf-app.com:80/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertNull(
            defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.URL,
            defs.get(defs.size() - 1).getType()
        );

    }

    @Test
    public void testLegacySamlProfileHttpsMetaUrlWithoutPort() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.uaa-acceptance.cf-app.com/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertFalse(
            context.getBean(BootstrapSamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions().isEmpty()
        );
        assertNull(
            defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.URL,
            defs.get(defs.size() - 1).getType()
        );

    }

    @Test
    public void testSamlProfileWithEntityIDAsURL() throws Exception {
        System.setProperty("login.entityID", "http://some.other.hostname:8080/saml");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class));
        assertEquals("http://some.other.hostname:8080/saml", context.getBean("samlSPAlias", String.class));
        assertEquals("some.other.hostname", context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class).getAlias());

    }

    @Test
    public void testSamlProfileWithEntityIDAsURLButAliasSet() throws Exception {
        System.setProperty("login.entityID", "http://some.other.hostname:8080/saml");
        System.setProperty("login.saml.entityIDAlias", "spalias");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class));
        assertEquals("spalias", context.getBean("samlSPAlias", String.class));
        assertEquals("spalias", context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class).getAlias());
    }

    @Test
    public void testMessageService() throws Exception {
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        Object messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(EmailService.class, messageService.getClass());

        System.setProperty("notifications.url", "");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(EmailService.class, messageService.getClass());

        System.setProperty("notifications.url", "example.com");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(NotificationsService.class, messageService.getClass());
    }

    private ConfigurableApplicationContext getServletContext(String profiles, String loginYmlPath, String uaaYamlPath, String... resources) {
        return getServletContext(profiles, false, new String[] {"required_configuration.yml", loginYmlPath, uaaYamlPath}, false, resources);
    }
    private ConfigurableApplicationContext getServletContext(String profiles, boolean mergeProfiles, String loginYmlPath, String uaaYamlPath, String... resources) {
        return getServletContext(
            profiles,
            mergeProfiles,
            new String[] {"required_configuration.yml", loginYmlPath, uaaYamlPath},
            false,
            resources
        );
    }
    private ConfigurableApplicationContext getServletContext(String profiles, boolean mergeProfiles, String[] yamlFiles, String... resources) {
        return getServletContext(
            profiles,
            mergeProfiles,
            yamlFiles,
            false,
            resources
        );
    }
    private static ConfigurableApplicationContext getServletContext(String profiles, boolean mergeProfiles, String[] yamlFiles, boolean cleandb, String... resources) {
        String[] resourcesToLoad = resources;
        if (!resources[0].endsWith(".xml")) {
            resourcesToLoad = new String[resources.length - 1];
            System.arraycopy(resources, 1, resourcesToLoad, 0, resourcesToLoad.length);
        }

        final String[] configLocations = resourcesToLoad;

        AbstractRefreshableWebApplicationContext context = new AbstractRefreshableWebApplicationContext() {

            @Override
            protected void loadBeanDefinitions(DefaultListableBeanFactory beanFactory) throws BeansException,
                IOException {
                XmlBeanDefinitionReader beanDefinitionReader = new XmlBeanDefinitionReader(beanFactory);

                // Configure the bean definition reader with this context's
                // resource loading environment.
                beanDefinitionReader.setEnvironment(this.getEnvironment());
                beanDefinitionReader.setResourceLoader(this);
                beanDefinitionReader.setEntityResolver(new ResourceEntityResolver(this));

                if (configLocations != null) {
                    for (String configLocation : configLocations) {
                        beanDefinitionReader.loadBeanDefinitions(configLocation);
                    }
                }
            }

        };

        if (profiles != null) {
            if (mergeProfiles) {
                String[] activeProfiles = context.getEnvironment().getActiveProfiles();
                HashSet<String> envProfiles = new HashSet<>(Arrays.asList(activeProfiles));
                envProfiles.addAll(Arrays.asList(StringUtils.commaDelimitedListToStringArray(profiles)));
                envProfiles.add("strict");
                context.getEnvironment().setActiveProfiles(envProfiles.toArray(new String[0]));
            } else {
                context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
            }
        }

        MockServletContext servletContext = new MockServletContext() {
            @Override
            public RequestDispatcher getNamedDispatcher(String path) {
                return new MockRequestDispatcher("/");
            }

            @Override
            public String getVirtualServerName() {
                return "localhost";
            }
        };
        context.setServletContext(servletContext);
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        servletConfig.addInitParameter("environmentConfigLocations", StringUtils.arrayToCommaDelimitedString(yamlFiles));
        context.setServletConfig(servletConfig);

        YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();
        initializer.initialize(context);

        if (profiles != null) {
            context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
        }

        context.refresh();
        if (cleandb) {
            context.getBean(Flyway.class).clean();
            context.getBean(Flyway.class).migrate();
        }

        return context;
    }
}
