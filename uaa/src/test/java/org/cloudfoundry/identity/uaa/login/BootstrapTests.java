/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.account.ResetPasswordController;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.NotificationsService;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenStore;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGenerator;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.cloudfoundry.identity.uaa.zone.KeyPair;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.beans.BeansException;
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
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import javax.servlet.RequestDispatcher;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.comparesEqualTo;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.ACCEPT_LANGUAGE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_LANGUAGE;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

public class BootstrapTests {

    private ConfigurableApplicationContext context;

    private static String activeProfiles;

    @BeforeClass
    public static void saveProfiles() {
        activeProfiles = System.getProperty("spring.profiles.active");
    }

    @AfterClass
    public static void restoreProfiles() {
        if (activeProfiles != null) {
            System.setProperty("spring.profiles.active", activeProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

    @Before
    public void setup() throws Exception {
        System.clearProperty("spring.profiles.active");
        IdentityZoneHolder.clear();
    }

    @After
    public void cleanup() throws Exception {
        System.clearProperty("spring.profiles.active");
        System.clearProperty("uaa.url");
        System.clearProperty("login.url");
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
    public void testRootContextDefaults() throws Exception {
        context = getServletContext(null, "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        assertEquals(864000, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
        IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
        Set<String> defaultHostnames = new HashSet<>(Arrays.asList("localhost"));
        assertEquals(filter.getDefaultZoneHostnames(), defaultHostnames);

        assertSame(UaaTokenStore.class, context.getBean(AuthorizationCodeServices.class).getClass());

        //check java mail sender
        EmailService emailService = context.getBean("emailService", EmailService.class);
        Field f = ReflectionUtils.findField(EmailService.class, "mailSender");
        assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", f);
        String smtpHost = context.getEnvironment().getProperty("smtp.host");
        if (smtpHost==null || smtpHost.length()==0) {
            assertEquals(FakeJavaMailSender.class, emailService.getMailSender().getClass());
        } else {
            assertEquals(JavaMailSenderImpl.class, emailService.getMailSender().getClass());
        }
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
        LockoutPolicy globalLockoutPolicy = globalPeriodLockoutPolicy.getLockoutPolicy();
        Assert.assertThat(globalLockoutPolicy.getLockoutAfterFailures(), equalTo(5));
        Assert.assertThat(globalLockoutPolicy.getCountFailuresWithin(), equalTo(3600));
        Assert.assertThat(globalLockoutPolicy.getLockoutPeriodSeconds(), equalTo(300));

        PeriodLockoutPolicy periodLockoutPolicy = context.getBean("defaultUaaLockoutPolicy", PeriodLockoutPolicy.class);
        LockoutPolicy lockoutPolicy = periodLockoutPolicy.getLockoutPolicy();
        Assert.assertThat(lockoutPolicy.getLockoutAfterFailures(), equalTo(5));
        Assert.assertThat(lockoutPolicy.getCountFailuresWithin(), equalTo(3600));
        Assert.assertThat(lockoutPolicy.getLockoutPeriodSeconds(), equalTo(300));

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
        assertEquals("One Time Code ( Get one at http://localhost:8080/uaa/passcode )",passcode.getDetails()[1]);

        ZoneAwareMetadataGenerator zoneAwareMetadataGenerator = context.getBean(ZoneAwareMetadataGenerator.class);
        assertTrue(zoneAwareMetadataGenerator.isRequestSigned());
        assertFalse(zoneAwareMetadataGenerator.isWantAssertionSigned());

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
        assertThat(corFilter.getDefaultConfiguration().getAllowedMethods(), containsInAnyOrder("OPTIONS", "GET", "POST", "PUT", "DELETE"));

        assertTrue(corFilter.getXhrConfiguration().isAllowedCredentials());
        assertFalse(corFilter.getDefaultConfiguration().isAllowedCredentials());
    }

    @Test
    public void testPropertyValuesWhenSetInYaml() throws Exception {
        try {
            String uaa = "uaa.some.test.domain.com";
            String login = uaa.replace("uaa", "login");
            System.setProperty("login.prompt.username.text","Username");
            System.setProperty("login.prompt.password.text","Your Secret");

            System.setProperty("smtp.host", "");
            System.setProperty("uaa.url", "https://" + uaa + ":555/uaa");
            System.setProperty("login.url", "https://" + login + ":555/uaa");
            System.setProperty("database.maxactive", "50");
            System.setProperty("database.maxidle", "5");
            System.setProperty("database.removeabandoned", "true");
            System.setProperty("database.logabandoned", "false");
            System.setProperty("database.abandonedtimeout", "45");
            System.setProperty("database.evictionintervalms", "30000");
            System.setProperty("database.caseinsensitive", "true");

            System.setProperty("password.policy.minLength", "8");
            System.setProperty("password.policy.maxLength", "100");
            System.setProperty("password.policy.requireUpperCaseCharacter", "0");
            System.setProperty("password.policy.requireLowerCaseCharacter", "0");
            System.setProperty("password.policy.requireDigit", "0");
            System.setProperty("password.policy.requireSpecialCharacter", "1");
            System.setProperty("password.policy.expirePasswordInMonths", "6");

            System.setProperty("password.policy.global.minLength", "8");
            System.setProperty("password.policy.global.maxLength", "100");
            System.setProperty("password.policy.global.requireUpperCaseCharacter", "0");
            System.setProperty("password.policy.global.requireLowerCaseCharacter", "0");
            System.setProperty("password.policy.global.requireDigit", "0");
            System.setProperty("password.policy.global.requireSpecialCharacter", "1");
            System.setProperty("password.policy.global.expirePasswordInMonths", "6");

            System.setProperty("authentication.policy.lockoutAfterFailures", "10");
            System.setProperty("authentication.policy.countFailuresWithinSeconds", "7200");
            System.setProperty("authentication.policy.lockoutPeriodSeconds", "600");

            System.setProperty("authentication.policy.global.lockoutAfterFailures", "1");
            System.setProperty("authentication.policy.global.countFailuresWithinSeconds", "2222");
            System.setProperty("authentication.policy.global.lockoutPeriodSeconds", "152");

            System.setProperty("jwt.token.policy.global.accessTokenValiditySeconds", "3600");
            System.setProperty("jwt.token.policy.global.refreshTokenValiditySeconds", "7200");

            System.setProperty("jwt.token.policy.accessTokenValiditySeconds", "4800");
            System.setProperty("jwt.token.policy.refreshTokenValiditySeconds", "9600");

            context = getServletContext(null, "login.yml", "test/hostnames/uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);

            assertThat(filter.getDefaultZoneHostnames(), containsInAnyOrder(uaa, login, "localhost", "host1.domain.com", "host2", "test3.localhost", "test4.localhost"));
            DataSource ds = context.getBean(DataSource.class);
            assertEquals(50, ds.getMaxActive());
            assertEquals(5, ds.getMaxIdle());
            assertTrue(ds.isRemoveAbandoned());
            assertFalse(ds.isLogAbandoned());
            assertEquals(45, ds.getRemoveAbandonedTimeout());
            assertEquals(30000, ds.getTimeBetweenEvictionRunsMillis());
            assertTrue(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
            //check java mail sender
            EmailService emailService = context.getBean("emailService", EmailService.class);
            assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", emailService.getMailSender());
            assertEquals(FakeJavaMailSender.class, emailService.getMailSender().getClass());

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

            PeriodLockoutPolicy periodLockoutPolicy = context.getBean("defaultUaaLockoutPolicy", PeriodLockoutPolicy.class);
            LockoutPolicy lockoutPolicy = periodLockoutPolicy.getLockoutPolicy();
            Assert.assertThat(lockoutPolicy.getLockoutAfterFailures(), equalTo(10));
            Assert.assertThat(lockoutPolicy.getCountFailuresWithin(), equalTo(7200));
            Assert.assertThat(lockoutPolicy.getLockoutPeriodSeconds(), equalTo(600));

            PeriodLockoutPolicy globalPeriodLockoutPolicy = context.getBean("globalPeriodLockoutPolicy", PeriodLockoutPolicy.class);
            LockoutPolicy globalLockoutPolicy = globalPeriodLockoutPolicy.getLockoutPolicy();
            Assert.assertThat(globalLockoutPolicy.getLockoutAfterFailures(), equalTo(1));
            Assert.assertThat(globalLockoutPolicy.getCountFailuresWithin(), equalTo(2222));
            Assert.assertThat(globalLockoutPolicy.getLockoutPeriodSeconds(), equalTo(152));

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

        } finally {

            System.clearProperty("login.prompt.username.text");
            System.clearProperty("login.prompt.password.text");

            System.clearProperty("database.maxactive");
            System.clearProperty("database.maxidle");
            System.clearProperty("database.removeabandoned");
            System.clearProperty("database.logabandoned");
            System.clearProperty("database.abandonedtimeout");
            System.clearProperty("database.evictionintervalms");
            System.clearProperty("smtp.host");

            System.clearProperty("password.policy.minLength");
            System.clearProperty("password.policy.maxLength");
            System.clearProperty("password.policy.requireUpperCaseCharacter");
            System.clearProperty("password.policy.requireLowerCaseCharacter");
            System.clearProperty("password.policy.requireDigit");
            System.clearProperty("password.policy.requireSpecialCharacter");
            System.clearProperty("password.policy.expirePasswordInMonths");

            System.clearProperty("password.policy.global.minLength");
            System.clearProperty("password.policy.global.maxLength");
            System.clearProperty("password.policy.global.requireUpperCaseCharacter");
            System.clearProperty("password.policy.global.requireLowerCaseCharacter");
            System.clearProperty("password.policy.global.requireDigit");
            System.clearProperty("password.policy.global.requireSpecialCharacter");
            System.clearProperty("password.policy.global.expirePasswordInMonths");

            System.clearProperty("authentication.policy.lockoutAfterFailures");
            System.clearProperty("authentication.policy.countFailuresWithinSeconds");
            System.clearProperty("authentication.policy.lockoutPeriodSeconds");

            System.clearProperty("authentication.policy.global.lockoutAfterFailures");
            System.clearProperty("authentication.policy.global.countFailuresWithinSeconds");
            System.clearProperty("authentication.policy.global.lockoutPeriodSeconds");
            System.clearProperty("token.policy.global.accessTokenValiditySeconds");
            System.clearProperty("token.policy.global.refreshTokenValiditySeconds");
            System.clearProperty("token.policy.refreshTokenValiditySeconds");
            System.clearProperty("token.policy.refreshTokenValiditySeconds");
        }
    }

    @Test
    public void testDefaultInternalHostnamesAndNoDBSettings() throws Exception {
        try {
            System.setProperty("smtp.host","localhost");
            //travis profile script overrides these properties
            System.setProperty("database.maxactive", "100");
            System.setProperty("database.maxidle", "10");
            String uaa = "uaa.some.test.domain.com";
            String login = uaa.replace("uaa", "login");
            System.setProperty("uaa.url", "https://" + uaa + ":555/uaa");
            System.setProperty("login.url", "https://" + login + ":555/uaa");
            context = getServletContext(null, "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
            Set<String> defaultHostnames = new HashSet<>(Arrays.asList(uaa, login, "localhost"));
            assertEquals(filter.getDefaultZoneHostnames(), defaultHostnames);
            DataSource ds = context.getBean(DataSource.class);
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
            //check java mail sender
            EmailService emailService = context.getBean("emailService", EmailService.class);
            assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", emailService.getMailSender());
            assertEquals(JavaMailSenderImpl.class, emailService.getMailSender().getClass());

        } finally {
            System.clearProperty("database.maxactive");
            System.clearProperty("database.maxidle");
        }
    }

    @Test
    public void bootstrap_scim_groups_from_yaml() throws Exception {
        context = getServletContext(null, "login.yml", "test/bootstrap/uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll();
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));
    }

    @Test
    public void testBootstrappedIdps_and_ExcludedClaims_and_CorsConfig() throws Exception {

        //generate login.yml with SAML and uaa.yml with LDAP
        System.setProperty("database.caseinsensitive", "false");
        context = getServletContext("ldap,default", true, "test/bootstrap/login.yml,login.yml","test/bootstrap/uaa.yml,uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        SamlIdentityProviderConfigurator samlProviders = context.getBean("metaDataProviders", SamlIdentityProviderConfigurator.class);
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
        assertEquals("Test LDAP Provider Description", ldapProvider.getConfig().getProviderDescription());

        IdentityProvider<SamlIdentityProviderDefinition> samlProvider =
            providerProvisioning.retrieveByOrigin("okta-local", IdentityZone.getUaa().getId());
        assertEquals("Test Okta Preview 1 Description", samlProvider.getConfig().getProviderDescription());

        CorsFilter filter = context.getBean(CorsFilter.class);

        for (CorsFilter.CorsConfiguration configuration : Arrays.asList(filter.getXhrConfiguration(), filter.getDefaultConfiguration())) {
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
    public void bootstrap_map_of_signing_and_verification_keys_in_default_zone() {
        context = getServletContext("ldap,default", true, "test/bootstrap/login.yml,login.yml", "test/bootstrap/uaa.yml,uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        TokenPolicy uaaTokenPolicy = context.getBean("uaaTokenPolicy", TokenPolicy.class);
        assertThat(uaaTokenPolicy, is(notNullValue()));
        assertThat(uaaTokenPolicy.getKeys().size(), comparesEqualTo(1));
        Map<String, KeyPair> keys = uaaTokenPolicy.getKeys();
        assertThat(keys.keySet(), contains("key-id-1"));
        KeyPair key = keys.get("key-id-1");
        assertThat(key.getSigningKey(), containsString("test-signing-key"));
        assertThat(key.getVerificationKey(), containsString("test-verification-key"));
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
        assertFalse(context.getBean(SamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(0, context.getBean(SamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions().size());
        SimpleUrlLogoutSuccessHandler handler = context.getBean(SimpleUrlLogoutSuccessHandler.class);
        Method getDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "getDefaultTargetUrl");
        getDefaultTargetUrl.setAccessible(true);
        Method isAlwaysUseDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "isAlwaysUseDefaultTargetUrl");
        isAlwaysUseDefaultTargetUrl.setAccessible(true);
        assertEquals(true, ReflectionUtils.invokeMethod(isAlwaysUseDefaultTargetUrl, handler));
        assertEquals("/login", ReflectionUtils.invokeMethod(getDefaultTargetUrl, handler));
    }

    @Test
    public void testLogoutRedirectConfiguration() throws Exception {
        System.setProperty("logout.redirect.parameter.disable", "false");
        System.setProperty("logout.redirect.url", "/login?parameter=true");
        try {
            context = getServletContext("default", "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            SimpleUrlLogoutSuccessHandler handler = context.getBean(SimpleUrlLogoutSuccessHandler.class);
            Method getDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "getDefaultTargetUrl");
            getDefaultTargetUrl.setAccessible(true);
            Method isAlwaysUseDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "isAlwaysUseDefaultTargetUrl");
            isAlwaysUseDefaultTargetUrl.setAccessible(true);
            assertEquals(false, ReflectionUtils.invokeMethod(isAlwaysUseDefaultTargetUrl, handler));
            assertEquals("/login?parameter=true", ReflectionUtils.invokeMethod(getDefaultTargetUrl, handler));
        } finally {
            System.clearProperty("logout.redirect.parameter.disable");
            System.clearProperty("logout.redirect.url");
        }
    }

    @Test
    public void testLegacySamlHttpMetaUrl() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.identity.cf-app.com/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPFile");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(SamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(SamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertNotNull(findProvider(defs, "testIDPFile"));
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.URL,
            findProvider(defs, "testIDPFile").getType());
        assertEquals(
            DefaultProtocolSocketFactory.class.getName(),
            findProvider(defs, "testIDPFile").getSocketFactoryClassName()
        );
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
        List<SamlIdentityProviderDefinition> defs = context.getBean(SamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertEquals(
            SamlIdentityProviderDefinition.MetadataLocation.DATA,
            findProvider(defs, "testIDPData").getType());
    }


    @Test
    public void testLegacySamlProfileHttpsMetaUrl() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "https://simplesamlphp.identity.cf-app.com:443/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(SamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(SamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertEquals(
            EasySSLProtocolSocketFactory.class.getName(),
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
        System.setProperty("login.idpMetadataURL", "https://simplesamlphp.identity.cf-app.com/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(SamlIdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(SamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertFalse(
            context.getBean(SamlIdentityProviderConfigurator.class).getIdentityProviderDefinitions().isEmpty()
        );
        assertEquals(
            EasySSLProtocolSocketFactory.class.getName(),
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
        return getServletContext(profiles, false, loginYmlPath, uaaYamlPath, resources);
    }
    private ConfigurableApplicationContext getServletContext(String profiles, boolean mergeProfiles, String loginYmlPath, String uaaYamlPath, String... resources) {
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
        servletConfig.addInitParameter("environmentConfigLocations", loginYmlPath+","+uaaYamlPath);
        context.setServletConfig(servletConfig);

        YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();
        initializer.initialize(context);

        if (profiles != null) {
            context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
        }

        context.refresh();

        return context;
    }
}
