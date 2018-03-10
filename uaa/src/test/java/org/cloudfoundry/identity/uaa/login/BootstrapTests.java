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

import javax.servlet.RequestDispatcher;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EventListener;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;
import java.util.stream.Collectors;

import org.cloudfoundry.identity.uaa.account.ResetPasswordController;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.health.HealthzEndpoint;
import org.cloudfoundry.identity.uaa.home.HomeController;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.NotificationsService;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.metrics.UaaMetricsFilter;
import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.JdbcMfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mock.oauth.CheckDefaultAuthoritiesMvcMockTests;
import org.cloudfoundry.identity.uaa.oauth.CheckTokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenStore;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenEndpoint;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlEntryPoint;
import org.cloudfoundry.identity.uaa.provider.saml.SamlSessionStorageFactory;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGenerator;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareSamlSecurityConfiguration;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.web.HeaderFilter;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.web.SessionIdleTimeoutSetter;
import org.cloudfoundry.identity.uaa.web.UaaSessionCookieConfig;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.CorsConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;

import org.apache.tomcat.jdbc.pool.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.storage.SAMLMessageStorageFactory;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm.SHA256;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm.SHA512;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.comparesEqualTo;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItemInArray;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.ACCEPT_LANGUAGE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_LANGUAGE;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

public class BootstrapTests {

    private ConfigurableApplicationContext context;

    private static String systemConfiguredProfiles;
    private String profiles;

    @BeforeClass
    public static void saveProfiles() {
        systemConfiguredProfiles = System.getProperty("spring.profiles.active");
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
    }

    @After
    public synchronized void cleanup() throws Exception {
        TestUtils.cleanTestDatabaseData(context.getBean(JdbcTemplate.class));
        System.clearProperty("spring.profiles.active");
        System.clearProperty("uaa.url");
        System.clearProperty("login.url");
        System.clearProperty("require_https");
        context.close();
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
    public void defaults_and_required_properties() throws Exception {
        System.clearProperty("spring.profiles.active");
        String originalSmtpHost = System.getProperty("smtp.host");
        System.setProperty("smtp.host","");

        context = getServletContext(profiles, false, new String[] {"login.yml", "uaa.yml", "required_configuration.yml"}, "file:./src/main/webapp/WEB-INF/spring-servlet.xml");

        JdbcRevocableTokenProvisioning revocableTokenProvisioning = context.getBean(JdbcRevocableTokenProvisioning.class);
        assertEquals(2500, revocableTokenProvisioning.getMaxExpirationRuntime());

        SessionIdleTimeoutSetter sessionIdleTimeoutSetter = context.getBean(SessionIdleTimeoutSetter.class);
        assertEquals(1800, sessionIdleTimeoutSetter.getTimeout());

        HealthzEndpoint hend = context.getBean(HealthzEndpoint.class);
        assertEquals(-1, hend.getSleepTime());

        UaaMetricsFilter metricsFilter = context.getBean(UaaMetricsFilter.class);
        assertTrue(metricsFilter.isEnabled());
        assertFalse(metricsFilter.isPerRequestMetrics());

        LimitedModeUaaFilter limitedModeUaaFilter = context.getBean(LimitedModeUaaFilter.class);
        assertNull(limitedModeUaaFilter.getStatusFile());
        assertFalse(limitedModeUaaFilter.isEnabled());
        assertThat(limitedModeUaaFilter.getPermittedEndpoints(),
                   containsInAnyOrder(
                        "/oauth/authorize/**",
                        "/oauth/token/**",
                        "/check_token/**",
                        "/login/**",
                        "/login.do",
                        "/logout/**",
                        "/logout.do",
                        "/saml/**",
                        "/autologin/**",
                        "/authenticate/**",
                        "/idp_discovery/**"
                   )
        );
        assertThat(limitedModeUaaFilter.getPermittedMethods(),
                   containsInAnyOrder(
                       "GET",
                       "HEAD",
                       "OPTIONS"
                   )
        );

        SAMLContextProvider basicContextProvider = context.getBean("basicContextProvider",SAMLContextProvider.class);
        SAMLMessageStorageFactory storageFactory = (SAMLMessageStorageFactory) ReflectionTestUtils.getField(basicContextProvider, "storageFactory");
        assertNotNull(storageFactory);
        assertEquals(SamlSessionStorageFactory.class, storageFactory.getClass());

        LoginSamlEntryPoint samlEntryPoint = context.getBean(LoginSamlEntryPoint.class);
        assertEquals("cloudfoundry-uaa-sp", samlEntryPoint.getDefaultProfileOptions().getRelayState());

        Collection<String> defaultZoneGroups = context.getBean("defaultUserAuthorities", Collection.class);
        String[] expectedZoneGroups = CheckDefaultAuthoritiesMvcMockTests.EXPECTED_DEFAULT_GROUPS;
        assertThat(defaultZoneGroups,containsInAnyOrder(expectedZoneGroups));
        IdentityZone defaultZone = context.getBean(IdentityZoneProvisioning.class).retrieve(IdentityZone.getUaa().getId());
        assertNotNull(defaultZone);
        assertThat(defaultZone.getConfig().getUserConfig().getDefaultGroups(),containsInAnyOrder(expectedZoneGroups));

        HeaderFilter filterWrapper = context.getBean(HeaderFilter.class);
        assertNotNull(filterWrapper);
        assertThat(
            Arrays.asList("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Prefix", "Forwarded"),
            containsInAnyOrder(filterWrapper.getFilteredHeaderNames().toArray())
        );

        UaaTokenEndpoint tokenEndpoint = context.getBean(UaaTokenEndpoint.class);
        CheckTokenEndpoint checkEndpoint = context.getBean(CheckTokenEndpoint.class);
        assertNotNull(tokenEndpoint.isAllowQueryString());
        assertTrue(tokenEndpoint.isAllowQueryString());
        assertNotNull(checkEndpoint.isAllowQueryString());
        assertTrue(checkEndpoint.isAllowQueryString());
        assertThat((Set<HttpMethod>) ReflectionTestUtils.getField(tokenEndpoint, "allowedRequestMethods"), containsInAnyOrder(HttpMethod.POST, HttpMethod.GET));

        for (String expectedProfile : StringUtils.commaDelimitedListToSet(profiles)) {
            String[] springProfiles = context.getEnvironment().getActiveProfiles();
            assertThat("expecting configured profiles to be set", springProfiles, hasItemInArray(expectedProfile));
        }

        Object messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(EmailService.class, messageService.getClass());

        IdentityZoneConfigurationBootstrap zoneConfigurationBootstrap = context.getBean(IdentityZoneConfigurationBootstrap.class);
        assertFalse(zoneConfigurationBootstrap.isIdpDiscoveryEnabled());

        DataSource ds = context.getBean(DataSource.class);
        assertEquals(0, ds.getMinIdle());
        assertEquals(100, ds.getMaxActive());
        assertEquals(10, ds.getMaxIdle());
        assertFalse(ds.isRemoveAbandoned());
        assertTrue(ds.isLogAbandoned());
        assertEquals(300, ds.getRemoveAbandonedTimeout());
        assertEquals(15000, ds.getTimeBetweenEvictionRunsMillis());

        if ("mysql".equals(context.getBean("platform"))) {
            assertTrue(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
        } else {
            assertFalse(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
        }

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
        assertFalse(zoneConfiguration.getSamlConfig().isDisableInResponseToCheck());

        assertEquals(SamlConfig.LEGACY_KEY_ID, zoneConfiguration.getSamlConfig().getActiveKeyId());
        assertEquals(1, zoneConfiguration.getSamlConfig().getKeys().size());

        assertFalse(zoneConfiguration.isAccountChooserEnabled());
        assertTrue(zoneConfiguration.getLinks().getSelfService().isSelfServiceLinksEnabled());
        assertNull(context.getBean("globalLinks", Links.class).getSelfService().getPasswd());
        assertNull(context.getBean("globalLinks", Links.class).getSelfService().getSignup());
        assertNull(context.getBean("globalLinks", Links.class).getHomeRedirect());
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

        TokenPolicy uaaTokenPolicy = context.getBean("uaaTokenPolicy",TokenPolicy.class);
        Assert.assertThat(uaaTokenPolicy.getAccessTokenValidity(), equalTo(60 * 60 * 12));
        Assert.assertThat(uaaTokenPolicy.getRefreshTokenValidity(), equalTo(60 * 60 * 24 * 30));
        assertEquals(false, uaaTokenPolicy.isRefreshTokenUnique());
        assertEquals(JWT.getStringValue(), uaaTokenPolicy.getRefreshTokenFormat());


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
    public void all_properties_set() throws Exception {
        String uaa = "uaa.some.test.domain.com";
        String login = uaa.replace("uaa", "login");
        String profiles = System.getProperty("spring.profiles.active");
        context = getServletContext(profiles, false, new String[] {"login.yml", "uaa.yml", "test/bootstrap/all-properties-set.yml"}, "file:./src/main/webapp/WEB-INF/spring-servlet.xml");

        JdbcRevocableTokenProvisioning revocableTokenProvisioning = context.getBean(JdbcRevocableTokenProvisioning.class);
        assertEquals(3000, revocableTokenProvisioning.getMaxExpirationRuntime());

        SessionIdleTimeoutSetter sessionIdleTimeoutSetter = context.getBean(SessionIdleTimeoutSetter.class);
        assertEquals(300, sessionIdleTimeoutSetter.getTimeout());

        HealthzEndpoint hend = context.getBean(HealthzEndpoint.class);
        assertEquals(5000, hend.getSleepTime());

        UaaMetricsFilter metricsFilter = context.getBean(UaaMetricsFilter.class);
        assertFalse(metricsFilter.isEnabled());
        assertTrue(metricsFilter.isPerRequestMetrics());

        LimitedModeUaaFilter limitedModeUaaFilter = context.getBean(LimitedModeUaaFilter.class);
        assertEquals("/tmp/uaa-test-limited-mode-status-file.txt", limitedModeUaaFilter.getStatusFile().getAbsolutePath());
        assertThat(limitedModeUaaFilter.getPermittedEndpoints(),
                   containsInAnyOrder(
                       "/oauth/authorize/**",
                       "/oauth/token/**",
                       "/check_token",
                       "/saml/**",
                       "/login/**",
                       "/logout/**",
                       "/other-url/**"
                   )
        );
        assertThat(limitedModeUaaFilter.getPermittedMethods(),
                   containsInAnyOrder(
                       "GET",
                       "HEAD",
                       "OPTIONS",
                       "CONNECT"
                   )
        );

        ScimGroupExternalMembershipManager externalMembershipManager = context.getBean(ScimGroupExternalMembershipManager.class);
        List<ScimGroupExternalMember> externalGroupMappings = externalMembershipManager.getExternalGroupMappings(IdentityZone.getUaa().getId());
        Set<String> externalLdapGroups = externalGroupMappings
            .stream()
            .filter(eq -> OriginKeys.LDAP.equals(eq.getOrigin()))
            .map(eg -> eg.getExternalGroup())
            .collect(Collectors.toSet());
        System.out.println("ExternalGroups:"+externalLdapGroups);
        assertThat(externalLdapGroups,
                   containsInAnyOrder(
                       "cn=admins,ou=user accounts,dc=mydomain,dc=com"
                   )
        );
        Set<String> internalLdapGroups = externalGroupMappings
            .stream()
            .filter(eq -> OriginKeys.LDAP.equals(eq.getOrigin()))
            .map(eg -> eg.getDisplayName())
            .collect(Collectors.toSet());
        System.out.println("InternalLdapGroups:"+internalLdapGroups);
        assertThat(internalLdapGroups,
                   containsInAnyOrder(
                       "bosh.admin",
                       "scim.read"
                   )
        );
        Set<String> externalSamlGroups = externalGroupMappings
            .stream()
            .filter(eq -> "some-saml-provider".equals(eq.getOrigin()))
            .map(eg -> eg.getExternalGroup())
            .collect(Collectors.toSet());
        assertThat(externalSamlGroups,
                   containsInAnyOrder(
                       "saml-bosh-admin-group",
                       "saml-admin-group"
                   )
        );
        Set<String> internalSamlGroups = externalGroupMappings
            .stream()
            .filter(eq -> "some-saml-provider".equals(eq.getOrigin()))
            .map(eg -> eg.getDisplayName())
            .collect(Collectors.toSet());
        assertThat(internalSamlGroups,
                   containsInAnyOrder(
                       "bosh.admin",
                       "scim.read",
                       "scim.write"
                   )
        );



        Collection<String> defaultZoneGroups = context.getBean("defaultUserAuthorities", Collection.class);
        String[] expectedZoneGroups = {
            "openid",
            "scim.me",
            "cloud_controller.read",
            "cloud_controller.write",
            "cloud_controller_service_permissions.read",
            "password.write",
            "uaa.user",
            "approvals.me",
            "oauth.approvals",
            "notification_preferences.read",
            "notification_preferences.write",
            "profile",
            "roles",
            "user_attributes",
            "cloud_controller.user",
            "actuator.read",
            "foo.foo"
        };
        assertThat(defaultZoneGroups,containsInAnyOrder(expectedZoneGroups));
        IdentityZone defaultZone = context.getBean(IdentityZoneProvisioning.class).retrieve(IdentityZone.getUaa().getId());
        assertNotNull(defaultZone);
        assertThat(defaultZone.getConfig().getUserConfig().getDefaultGroups(),containsInAnyOrder(expectedZoneGroups));
        IdentityZoneHolder.set(defaultZone);

        HeaderFilter filterWrapper = context.getBean(HeaderFilter.class);
        assertNotNull(filterWrapper);
        assertThat(
            Arrays.asList("X-Forwarded-Host", "Forwarded"),
            containsInAnyOrder(filterWrapper.getFilteredHeaderNames().toArray())
        );

        UaaTokenEndpoint tokenEndpoint = context.getBean(UaaTokenEndpoint.class);
        CheckTokenEndpoint checkEndpoint = context.getBean(CheckTokenEndpoint.class);
        assertNotNull(tokenEndpoint.isAllowQueryString());
        assertFalse(tokenEndpoint.isAllowQueryString());
        assertNotNull(checkEndpoint.isAllowQueryString());
        assertFalse(checkEndpoint.isAllowQueryString());
        assertThat((Set<HttpMethod>) ReflectionTestUtils.getField(tokenEndpoint, "allowedRequestMethods"), containsInAnyOrder(HttpMethod.POST));

        JdbcTemplate template = context.getBean(JdbcTemplate.class);
        assertEquals(0, (int)template.queryForObject("SELECT count(*) FROM oauth_client_details WHERE client_id IN (?,?) AND identity_zone_id = ?", Integer.class, "client-should-not-exist-1", "client-should-not-exist-2", IdentityZone.getUaa().getId()));
        assertEquals(0, (int)template.queryForObject("SELECT count(*) FROM users WHERE username IN (?,?) AND identity_zone_id = ?", Integer.class, "delete-user-1", "delete-user-2", IdentityZone.getUaa().getId()));

        Environment env = context.getEnvironment();
        assertEquals("test.com", env.getProperty("analytics.domain"));
        assertEquals("some-code", env.getProperty("analytics.code"));
        assertEquals("/resources/pivotal", env.getProperty("assetBaseUrl"));

        Object messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(NotificationsService.class, messageService.getClass());

        IdentityZoneConfigurationBootstrap zoneConfigurationBootstrap = context.getBean(IdentityZoneConfigurationBootstrap.class);
        assertTrue(zoneConfigurationBootstrap.isIdpDiscoveryEnabled());
        assertNotNull(zoneConfigurationBootstrap.getBranding());
        assertEquals(zoneConfigurationBootstrap.getBranding().get("companyName"), "test-company-branding-name");
        assertThat((String) zoneConfigurationBootstrap.getBranding().get("squareLogo"), containsString("this is an invalid"));
        assertThat((String) zoneConfigurationBootstrap.getBranding().get("productLogo"), containsString("base64 logo with"));


        assertThat(context.getBean(UaaTokenServices.class).getExcludedClaims(), containsInAnyOrder(ClaimConstants.AUTHORITIES));

        CorsFilter corsFilter = context.getBean(CorsFilter.class);

        for (CorsConfiguration configuration : Arrays.asList(corsFilter.getXhrConfiguration(), corsFilter.getDefaultConfiguration())) {
            assertEquals(1999999, configuration.getMaxAge());
            assertEquals(1, configuration.getAllowedUris().size());
            assertEquals(".*token$", configuration.getAllowedUris().get(0));
            assertEquals(1, configuration.getAllowedUriPatterns().size());
            assertTrue(configuration.isAllowedCredentials());
            assertThat(configuration.getAllowedHeaders(), containsInAnyOrder("Accept", "Content-Type"));
            assertThat(configuration.getAllowedOrigins(), containsInAnyOrder("^example.com.*", "foo.com"));
            assertThat(configuration.getAllowedMethods(), containsInAnyOrder("PUT", "POST", "GET"));
        }

        JdbcUaaUserDatabase userDatabase = context.getBean(JdbcUaaUserDatabase.class);
        assertTrue(userDatabase.isCaseInsensitive());
        UaaUser adminUser = userDatabase.retrieveUserByName("admin", OriginKeys.UAA);
        assertNotNull(adminUser);
        assertThat(adminUser.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList()), hasItems("uaa.admin", "foo.bar", "foo.foo"));


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
        assertTrue(zoneConfiguration.getSamlConfig().isDisableInResponseToCheck());

        assertEquals("key1", zoneConfiguration.getSamlConfig().getActiveKeyId());
        assertEquals(2, zoneConfiguration.getSamlConfig().getKeys().size());


        assertTrue(zoneConfiguration.isAccountChooserEnabled());
        assertFalse(zoneConfiguration.getLinks().getSelfService().isSelfServiceLinksEnabled());
        assertEquals("/configured_home_redirect", zoneConfiguration.getLinks().getHomeRedirect());
        assertEquals("/configured_signup", zoneConfiguration.getLinks().getSelfService().getSignup());
        assertEquals("/configured_passwd", zoneConfiguration.getLinks().getSelfService().getPasswd());
        assertEquals("https://{zone.subdomain}.myaccountmanager.domain.com/z/{zone.id}/create_account", context.getBean("globalLinks", Links.class).getSelfService().getSignup());
        assertEquals("https://{zone.subdomain}.myaccountmanager.domain.com/z/{zone.id}/forgot_password", context.getBean("globalLinks", Links.class).getSelfService().getPasswd());
        assertEquals("https://{zone.subdomain}.myaccountmanager.domain.com/z/{zone.id}/success", context.getBean("globalLinks", Links.class).getHomeRedirect());
        assertSame(context.getBean("globalLinks", Links.class), context.getBean(HomeController.class).getGlobalLinks());

        assertEquals("redirect", zoneConfiguration.getLinks().getLogout().getRedirectParameterName());
        assertEquals(false, zoneConfiguration.getLinks().getLogout().isDisableRedirectParameter());
        assertEquals("/configured_login", zoneConfiguration.getLinks().getLogout().getRedirectUrl());
        assertEquals(Arrays.asList("https://url1.domain1.com/logout-success","https://url2.domain2.com/logout-success"), zoneConfiguration.getLinks().getLogout().getWhitelist());
        assertFalse(zoneConfiguration.getLinks().getLogout().isDisableRedirectParameter());

        assertTrue(context.getBean(IdentityZoneProvisioning.class).retrieve(IdentityZone.getUaa().getId()).getConfig().getTokenPolicy().isJwtRevocable());
        ZoneAwareMetadataGenerator zoneAwareMetadataGenerator = context.getBean(ZoneAwareMetadataGenerator.class);
        assertFalse(zoneAwareMetadataGenerator.isWantAssertionSigned());
        assertFalse(zoneAwareMetadataGenerator.isRequestSigned());

        assertEquals(
            Arrays.asList(
                new Prompt("username", "text", "Username"),
                new Prompt("password", "password", "Your Secret"),
                new Prompt("passcode", "password", "One Time Code ( Get one at https://login.some.test.domain.com:555/uaa/passcode )")
            ),
            zoneConfiguration.getPrompts()
        );
        ClientSecretPolicy expectedSecretPolicy = new ClientSecretPolicy();
        expectedSecretPolicy.setMinLength(8);
        expectedSecretPolicy.setMaxLength(128);
        expectedSecretPolicy.setRequireUpperCaseCharacter(1);
        expectedSecretPolicy.setRequireLowerCaseCharacter(3);
        expectedSecretPolicy.setRequireDigit(2);
        expectedSecretPolicy.setRequireSpecialCharacter(0);
        expectedSecretPolicy.setExpireSecretInMonths(-1);

        assertEquals(expectedSecretPolicy, zoneConfiguration.getClientSecretPolicy());

        IdentityProviderProvisioning idpProvisioning = context.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = idpProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        assertTrue(uaaIdp.getConfig().isDisableInternalUserManagement());
        assertFalse(uaaIdp.isActive());

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcProvider = idpProvisioning.retrieveByOrigin("my-oidc-provider", IdentityZone.getUaa().getId());
        assertNotNull(oidcProvider);
        assertTrue(oidcProvider.getConfig().isClientAuthInBody());
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
        assertFalse(oidcProvider.getConfig().isStoreCustomAttributes());

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oauthProvider = idpProvisioning.retrieveByOrigin("my-oauth-provider", IdentityZone.getUaa().getId());
        assertNotNull(oauthProvider);
        assertFalse(oauthProvider.getConfig().isClientAuthInBody());
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
        assertFalse(oauthProvider.getConfig().isStoreCustomAttributes());

        IdentityProvider<OIDCIdentityProviderDefinition> defaultOauthProvider = idpProvisioning.retrieveByOrigin("default-discovery-provider", IdentityZone.getUaa().getId());
        assertNotNull(defaultOauthProvider);
        assertNull(defaultOauthProvider.getConfig().getAuthUrl());
        assertNull(defaultOauthProvider.getConfig().getTokenUrl());
        assertNull(defaultOauthProvider.getConfig().getIssuer());
        assertNull(defaultOauthProvider.getConfig().getTokenKeyUrl());
        assertEquals(new URL("https://accounts.google.com/.well-known/openid-configuration"), defaultOauthProvider.getConfig().getDiscoveryUrl());
        assertEquals(true, defaultOauthProvider.getConfig().isShowLinkText());
        assertEquals("uaa", defaultOauthProvider.getConfig().getRelyingPartyId());
        assertEquals("secret", defaultOauthProvider.getConfig().getRelyingPartySecret());
        assertEquals("default-discovery-provider", defaultOauthProvider.getOriginKey());
        assertTrue(defaultOauthProvider.getConfig().isAddShadowUserOnLogin());
        assertEquals(OIDC10, defaultOauthProvider.getType());
        assertEquals("code", defaultOauthProvider.getConfig().getResponseType());
        assertTrue(defaultOauthProvider.getConfig().isStoreCustomAttributes());
        assertFalse(defaultOauthProvider.getConfig().isSkipSslValidation());

        List<String> deletedIdps = Arrays.asList("delete-discovery-provider", "delete.local");
        for (String deleteOrigin : deletedIdps) {
            try {
                idpProvisioning.retrieveByOrigin(deleteOrigin, IdentityZone.getUaa().getId());
                fail("The identity provider '" + deleteOrigin + "' should have been deleted");
            } catch (EmptyResultDataAccessException e) {}
        }

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
        assertEquals("https://localhost:8443/uaa/oauth/token", uaaTokenServices.getIssuer());
        Assert.assertThat(uaaTokenServices.getTokenPolicy().getAccessTokenValidity(), equalTo(3600));
        Assert.assertThat(uaaTokenServices.getTokenPolicy().getRefreshTokenValidity(), equalTo(7200));

        TokenPolicy uaaTokenPolicy = context.getBean("uaaTokenPolicy", TokenPolicy.class);
        Assert.assertThat(uaaTokenPolicy.getAccessTokenValidity(), equalTo(4800));
        Assert.assertThat(uaaTokenPolicy.getRefreshTokenValidity(), equalTo(9600));

        assertThat(uaaTokenPolicy, is(notNullValue()));
        assertThat(uaaTokenPolicy.getKeys().size(), comparesEqualTo(2));
        assertEquals(true, uaaTokenPolicy.isRefreshTokenUnique());
        assertEquals(OPAQUE.getStringValue(), uaaTokenPolicy.getRefreshTokenFormat());
        Map<String, String> keys = uaaTokenPolicy.getKeys();
        assertTrue(keys.keySet().contains("key-id-1"));
        String signingKey = keys.get("key-id-1");
        assertThat(signingKey, containsString("test-signing-key"));
        assertThat(uaaTokenPolicy.getActiveKeyId(), is("key-id-2"));


        List<Prompt> prompts = (List<Prompt>) context.getBean("prompts");
        assertNotNull(prompts);
        assertEquals(3, prompts.size());
        Prompt passcode = prompts.get(0);
        assertEquals("Username", passcode.getDetails()[1]);
        passcode = prompts.get(1);
        assertEquals("Your Secret", passcode.getDetails()[1]);
        passcode = prompts.get(2);
        assertEquals("One Time Code ( Get one at https://login.some.test.domain.com:555/uaa/passcode )", passcode.getDetails()[1]);

        assertEquals(SHA256, context.getBean("defaultUaaSamlSignatureAlgorithm", SamlConfig.SignatureAlgorithm.class));
        assertEquals(SHA512, context.getBean("globalSamlSignatureAlgorithm", SamlConfig.SignatureAlgorithm.class));
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, context.getBean(ZoneAwareSamlSecurityConfiguration.class).getSignatureAlgorithmURI("RSA"));
        assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA256, context.getBean(ZoneAwareSamlSecurityConfiguration.class).getSignatureReferenceDigestMethod());

        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll(IdentityZoneHolder.get().getId());
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));

        BootstrapSamlIdentityProviderData samlProviders = context.getBean(BootstrapSamlIdentityProviderData.class);
        IdentityProviderProvisioning providerProvisioning = context.getBean("identityProviderProvisioning", IdentityProviderProvisioning.class);
        assertTrue(samlProviders.getIdentityProviderDefinitions().size() >= 4);
        //verify that they got loaded in the DB
        for (SamlIdentityProviderDefinition def : samlProviders.getIdentityProviderDefinitions()) {
            if (!deletedIdps.contains(def.getIdpEntityAlias())) {
                assertNotNull(providerProvisioning.retrieveByOrigin(def.getIdpEntityAlias(), IdentityZone.getUaa().getId()));
            }
        }

        assertEquals(3600, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
        assertFalse(context.getBean(BootstrapSamlIdentityProviderData.class).isLegacyMetadataTrustCheck());
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));


        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider =
            providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZone.getUaa().getId());
        assertNotNull(ldapProvider);
        LdapIdentityProviderDefinition ldapConfig = ldapProvider.getConfig();
        assertFalse(ldapConfig.isAddShadowUserOnLogin());
        assertEquals("Test LDAP Provider Description", ldapConfig.getProviderDescription());
        assertFalse(ldapConfig.isStoreCustomAttributes());

        //LDAP Group Validation
        assertEquals("ldap/ldap-groups-map-to-scopes.xml", ldapConfig.getLdapGroupFile());
        assertEquals("ou=all-groups,dc=test,dc=com", ldapConfig.getGroupSearchBase());
        assertTrue(ldapConfig.isGroupSearchSubTree());
        assertEquals("(member={0})", ldapConfig.getGroupSearchFilter());
        assertEquals(11, ldapConfig.getMaxGroupSearchDepth());
        assertTrue(ldapConfig.isAutoAddGroups());


        IdentityProvider<SamlIdentityProviderDefinition> samlProvider = providerProvisioning.retrieveByOrigin("okta-local", IdentityZone.getUaa().getId());
        assertEquals("Test Okta Preview 1 Description", samlProvider.getConfig().getProviderDescription());
        assertEquals(SamlIdentityProviderDefinition.ExternalGroupMappingMode.EXPLICITLY_MAPPED, samlProvider.getConfig().getGroupMappingMode());
        assertTrue(samlProvider.getConfig().isSkipSslValidation());
        assertFalse(samlProvider.getConfig().isStoreCustomAttributes());

        IdentityProvider<SamlIdentityProviderDefinition> samlProvider2 = providerProvisioning.retrieveByOrigin("okta-local-2", IdentityZone.getUaa().getId());
        assertEquals(SamlIdentityProviderDefinition.ExternalGroupMappingMode.AS_SCOPES, samlProvider2.getConfig().getGroupMappingMode());
        assertFalse(samlProvider2.getConfig().isSkipSslValidation());
        assertTrue(samlProvider2.getConfig().isStoreCustomAttributes());

        IdentityProvider<SamlIdentityProviderDefinition> samlProvider3 = providerProvisioning.retrieveByOrigin("vsphere.local", IdentityZone.getUaa().getId());
        assertTrue(samlProvider3.getConfig().isSkipSslValidation());

        ClientDetailsService clients = context.getBean(ClientDetailsService.class);
        ClientDetails ccSvcDashboard = clients.loadClientByClientId("cc-service-dashboards");
        assertNotNull(ccSvcDashboard);

        MfaProviderProvisioning mfaProviderProvisioning = context.getBean(JdbcMfaProviderProvisioning.class);
        MfaProvider<GoogleMfaProviderConfig> mfaProvider1 = mfaProviderProvisioning.retrieveByName("mfaprovider1", IdentityZoneHolder.getUaaZone().getId());
        assertNotNull(mfaProvider1);
        assertEquals("all-properties-set-description", mfaProvider1.getConfig().getProviderDescription());
        assertEquals("google.com", mfaProvider1.getConfig().getIssuer());

    }

    @Test
    public void xlegacy_test_deprecated_properties() throws Exception {
        context = getServletContext(null, "login.yml", "test/bootstrap/deprecated_properties_still_work.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll(IdentityZoneHolder.get().getId());
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));
        IdentityZoneConfigurationBootstrap zoneBootstrap = context.getBean(IdentityZoneConfigurationBootstrap.class);
        assertEquals("https://deprecated.home_redirect.com", zoneBootstrap.getHomeRedirect());
        IdentityZone defaultZone = context.getBean(IdentityZoneProvisioning.class).retrieve("uaa");
        IdentityZoneConfiguration defaultConfig = defaultZone.getConfig();
        assertTrue("Legacy SAML keys should be available", defaultConfig.getSamlConfig().getKeys().containsKey(SamlConfig.LEGACY_KEY_ID));
        assertEquals(SamlLoginServerKeyManagerTests.CERTIFICATE.trim(), defaultConfig.getSamlConfig().getCertificate().trim());
        assertEquals(SamlLoginServerKeyManagerTests.KEY.trim(), defaultConfig.getSamlConfig().getPrivateKey().trim());
        assertEquals(SamlLoginServerKeyManagerTests.PASSWORD.trim(), defaultConfig.getSamlConfig().getPrivateKeyPassword().trim());

    }

    @Test
    public void legacy_saml_idp_as_top_level_element() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.oms.identity.team/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPFile");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderData.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
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
    public void legacy_saml_metadata_as_xml() throws Exception {
        String metadataString = new Scanner(new File("./src/main/resources/sample-okta-localhost.xml")).useDelimiter("\\Z").next();
        System.setProperty("login.idpMetadata", metadataString);
        System.setProperty("login.idpEntityAlias", "testIDPData");
        context = getServletContext("default,saml,configMetadata", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.DATA,
            findProvider(defs, "testIDPData").getType());
    }


    @Test
    public void legacy_saml_metadata_as_url() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.oms.identity.team:80/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderData.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertNull(
            defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.URL,
            defs.get(defs.size() - 1).getType()
        );

    }

    @Test
    public void legacy_saml_url_without_port() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.oms.identity.team/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderData.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertFalse(
            context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions().isEmpty()
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
    public void saml_set_entity_id_to_url() throws Exception {
        System.setProperty("login.entityID", "http://some.other.hostname:8080/saml");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class));
        assertEquals("http://some.other.hostname:8080/saml", context.getBean("samlSPAlias", String.class));
        assertEquals("some.other.hostname", context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class).getAlias());
    }

    @Test
    public void saml_entity_alias_is_set() throws Exception {
        System.setProperty("login.entityID", "http://some.other.hostname:8080/saml");
        System.setProperty("login.saml.entityIDAlias", "spalias");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class));
        assertEquals("spalias", context.getBean("samlSPAlias", String.class));
        assertEquals("spalias", context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class).getAlias());
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

            @Override
            public <Type extends EventListener> void addListener(Type t) {
                //no op
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
