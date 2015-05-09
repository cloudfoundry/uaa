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
package org.cloudfoundry.identity.uaa.mock.ldap;

import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.ChainedAuthenticationManager;
import org.cloudfoundry.identity.uaa.ldap.ExtendedLdapUserMapper;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.ldap.ProcessLdapProperties;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderValidationRequest;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderValidationRequest.UsernamePasswordAuthentication;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.hamcrest.core.StringContains;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.server.ApacheDSContainer;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(Parameterized.class)
public class LdapMockMvcTests extends TestClassNullifier {

    private MockEnvironment mockEnvironment;

    @Parameters(name = "{index}: auth[{0}]; group[{1}]; url[{2}]")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {"ldap-simple-bind.xml", "ldap-groups-null.xml", "ldap://localhost:33389"},
            {"ldap-simple-bind.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389"},
            {"ldap-simple-bind.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389"},
            {"ldap-simple-bind.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636"},
            {"ldap-search-and-bind.xml", "ldap-groups-null.xml", "ldap://localhost:33389"},
            {"ldap-search-and-bind.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389"},
            {"ldap-search-and-bind.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389"},
            {"ldap-search-and-bind.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636"},
            {"ldap-search-and-compare.xml", "ldap-groups-null.xml", "ldap://localhost:33389"},
            {"ldap-search-and-compare.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389"},
            {"ldap-search-and-compare.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389"},
            {"ldap-search-and-compare.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636"}
        });
    }

    private static ApacheDsSSLContainer apacheDS;
    private static File tmpDir;

    @AfterClass
    public static void afterClass() {
        apacheDS.stop();
    }

    @BeforeClass
    public static void startApacheDS() throws Exception {
        tmpDir = new File(System.getProperty("java.io.tmpdir")+"/apacheds/"+new RandomValueStringGenerator().generate());
        tmpDir.deleteOnExit();
        System.out.println(tmpDir);
        //configure properties for running against ApacheDS
        apacheDS = new ApacheDsSSLContainer("dc=test,dc=com","classpath:ldap_init.ldif");
        apacheDS.setWorkingDirectory(tmpDir);
        apacheDS.setPort(33389);
        apacheDS.setSslPort(33636);
        apacheDS.afterPropertiesSet();
        apacheDS.start();
    }

    XmlWebApplicationContext webApplicationContext;

    MockMvc mockMvc;
    TestClient testClient;
    JdbcTemplate jdbcTemplate;
    JdbcScimGroupProvisioning gDB;
    JdbcScimUserProvisioning uDB;
    UaaUserDatabase userDatabase;

    private String ldapProfile;
    private String ldapGroup;
    private String ldapBaseUrl;

    public LdapMockMvcTests(String ldapProfile, String ldapGroup, String baseUrl) {
        this.ldapGroup = ldapGroup;
        this.ldapProfile = ldapProfile;
        this.ldapBaseUrl = baseUrl;
    }

    @Before
    public void createMockEnvironment() {
        mockEnvironment = new MockEnvironment();
        IdentityZoneHolder.clear();
    }

    public void setUp() throws Exception {
        mockEnvironment.setProperty("spring.profiles.active", "ldap,default");
        mockEnvironment.setProperty("ldap.profile.file", "ldap/" + ldapProfile);
        mockEnvironment.setProperty("ldap.groups.file", "ldap/" + ldapGroup);
        mockEnvironment.setProperty("ldap.group.maxSearchDepth", "10");
        mockEnvironment.setProperty("ldap.base.url",ldapBaseUrl);
        mockEnvironment.setProperty("ldap.base.userDn","cn=admin,ou=Users,dc=test,dc=com");
        mockEnvironment.setProperty("ldap.base.password","adminsecret");
        mockEnvironment.setProperty("ldap.ssl.skipverification","true");

        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(mockEnvironment);
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.getEnvironment().addActiveProfile("default");
        webApplicationContext.getEnvironment().addActiveProfile("ldap");
        webApplicationContext.refresh();

        List<String> profiles = Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles());
        Assume.assumeTrue(profiles.contains("ldap"));

        //we need to reinitialize the context if we change the ldap.profile.file property
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);
        jdbcTemplate = webApplicationContext.getBean(JdbcTemplate.class);
        LimitSqlAdapter limitSqlAdapter = webApplicationContext.getBean(LimitSqlAdapter.class);
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter);
        gDB = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);
        uDB = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory);
        userDatabase = webApplicationContext.getBean(UaaUserDatabase.class);
    }

    @After
    public void tearDown() throws Exception {
        System.clearProperty("ldap.profile.file");
        System.clearProperty("ldap.base.mailSubstitute");
        if (webApplicationContext!=null) {
            Flyway flyway = webApplicationContext.getBean(Flyway.class);
            flyway.clean();
            webApplicationContext.destroy();
        }
    }

    private void deleteLdapUsers() {
        jdbcTemplate.update("delete from users where origin='" + Origin.LDAP + "'");
    }

    @Test
    public void testLdapConfigurationBeforeSave() throws Exception {
        Assume.assumeThat("ldap-search-and-bind.xml", StringContains.containsString(ldapProfile));
        Assume.assumeThat("ldap-groups-map-to-scopes.xml", StringContains.containsString(ldapGroup));

        setUp();
        String identityAccessToken = MockMvcUtils.utils().getClientOAuthAccessToken(mockMvc, "identity", "identitysecret", "");
        String adminAccessToken = MockMvcUtils.utils().getClientOAuthAccessToken(mockMvc, "admin", "adminsecret", "");
        IdentityZone zone = MockMvcUtils.utils().createZoneUsingWebRequest(mockMvc, identityAccessToken);
        String zoneAdminToken = MockMvcUtils.utils().getZoneAdminToken(mockMvc, adminAccessToken, zone.getId());

        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:33389",
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret",
            "dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            null,
            false,
            true,
            true,
            10,
            true
        );

        IdentityProvider provider = new IdentityProvider();
        provider.setOriginKey(Origin.LDAP);
        provider.setName("Test ldap provider");
        provider.setType(Origin.LDAP);
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getId());

        UsernamePasswordAuthentication token = new UsernamePasswordAuthentication("marissa2", "ldap");

        IdentityProviderValidationRequest request = new IdentityProviderValidationRequest(provider, token);
        System.out.println("request = \n" + JsonUtils.writeValueAsString(request));
        //Happy Day Scenario
        MockHttpServletRequestBuilder post = post("/identity-providers/test")
            .header("Accept", APPLICATION_JSON_VALUE)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + zoneAdminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request))
            .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        MvcResult result = mockMvc.perform(post)
            .andExpect(status().isOk())
            .andReturn();

        assertEquals("\"ok\"", result.getResponse().getContentAsString());

        //Correct configuration, invalid credentials
        token = new UsernamePasswordAuthentication("marissa2", "koala");
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
            .header("Accept", APPLICATION_JSON_VALUE)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + zoneAdminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request))
            .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = mockMvc.perform(post)
            .andExpect(status().isExpectationFailed())
            .andReturn();
        assertEquals("\"bad credentials\"", result.getResponse().getContentAsString());

        //Insufficent scope
        post = post("/identity-providers/test")
            .header("Accept", APPLICATION_JSON_VALUE)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + identityAccessToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request))
            .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = mockMvc.perform(post)
            .andExpect(status().isForbidden())
            .andReturn();


        //Invalid LDAP configuration - change the password of search user
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:33389",
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret23",
            "dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            null,
            false,
            true,
            true,
            10,
            true
        );
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
            .header("Accept", APPLICATION_JSON_VALUE)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + zoneAdminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request))
            .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));

        //Invalid LDAP configuration - no ldap server
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:33388",
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret",
            "dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            null,
            false,
            true,
            true,
            10,
            true
        );
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
            .header("Accept", APPLICATION_JSON_VALUE)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + zoneAdminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request))
            .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));

        //Invalid LDAP configuration - invalid search base
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:33389",
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret",
            ",,,,,dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            null,
            false,
            true,
            true,
            10,
            true
        );
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
            .header("Accept", APPLICATION_JSON_VALUE)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + zoneAdminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request))
            .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));

        ProcessLdapProperties processLdapProperties = webApplicationContext.getBean(ProcessLdapProperties.class);
        if (processLdapProperties.isLdapsUrl()) {
            token = new UsernamePasswordAuthentication("marissa2", "ldap");

            //SSL self signed cert problems
            definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldaps://localhost:33636",
                "cn=admin,ou=Users,dc=test,dc=com",
                "adminsecret",
                "dc=test,dc=com",
                "cn={0}",
                "ou=scopes,dc=test,dc=com",
                "member={0}",
                "mail",
                null,
                false,
                true,
                true,
                10,
                false
            );
            provider.setConfig(JsonUtils.writeValueAsString(definition));
            request = new IdentityProviderValidationRequest(provider, token);
            post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
            result = mockMvc.perform(post)
                .andExpect(status().isBadRequest())
                .andReturn();
            assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));
            definition.setSkipSSLVerification(true);
            provider.setConfig(JsonUtils.writeValueAsString(definition));
            request = new IdentityProviderValidationRequest(provider, token);
            post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

            result = mockMvc.perform(post)
                .andExpect(status().isOk())
                .andReturn();
            assertThat(result.getResponse().getContentAsString(), containsString("\"ok\""));
        }
    }

    @Test
    public void testLoginInNonDefaultZone() throws Exception {
        Assume.assumeThat("ldap-search-and-bind.xml", StringContains.containsString(ldapProfile));
        Assume.assumeThat("ldap-groups-map-to-scopes.xml", StringContains.containsString(ldapGroup));

        setUp();
        String identityAccessToken = MockMvcUtils.utils().getClientOAuthAccessToken(mockMvc, "identity", "identitysecret", "");
        String adminAccessToken = MockMvcUtils.utils().getClientOAuthAccessToken(mockMvc, "admin", "adminsecret", "");
        IdentityZone zone = MockMvcUtils.utils().createZoneUsingWebRequest(mockMvc, identityAccessToken);
        String zoneAdminToken = MockMvcUtils.utils().getZoneAdminToken(mockMvc, adminAccessToken, zone.getId());

        mockMvc.perform(get("/login")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        //IDP not yet created
        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
            .param("username", "marissa2")
            .param("password", "ldap"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?error=login_failure"));

        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:33389",
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret",
            "dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            null,
            false,
            true,
            true,
            10,
            true
        );

        IdentityProvider provider = new IdentityProvider();
        provider.setOriginKey(Origin.LDAP);
        provider.setName("Test ldap provider");
        provider.setType(Origin.LDAP);
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getId());
        provider = MockMvcUtils.utils().createIdpUsingWebRequest(mockMvc, zone.getId(), zoneAdminToken, provider, status().isCreated());

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
            .param("username", "marissa2")
            .param("password", "ldap"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone);
        UaaUser user = userDatabase.retrieveUserByName("marissa2",Origin.LDAP);
        IdentityZoneHolder.clear();
        assertNotNull(user);
        assertEquals(Origin.LDAP, user.getOrigin());
        assertEquals(zone.getId(), user.getZoneId());

        provider.setActive(false);
        MockMvcUtils.utils().createIdpUsingWebRequest(mockMvc, zone.getId(), zoneAdminToken, provider, status().isOk(), true);
        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
            .param("username", "marissa2")
            .param("password", "ldap"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?error=login_failure"));


        provider.setActive(true);
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:33389",
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret",
            "dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            "{0}@ldaptest.com",
            true,
            true,
            true,
            10,
            true
        );
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        MockMvcUtils.utils().createIdpUsingWebRequest(mockMvc, zone.getId(), zoneAdminToken, provider, status().isOk(), true);

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
            .param("username", "marissa2")
            .param("password", "ldap"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone);
        user = userDatabase.retrieveUserByName("marissa2",Origin.LDAP);
        IdentityZoneHolder.clear();
        assertNotNull(user);
        assertEquals(Origin.LDAP, user.getOrigin());
        assertEquals(zone.getId(), user.getZoneId());
        assertEquals("marissa2@ldaptest.com", user.getEmail());
    }


    @Test
    public void runLdapTestblock() throws Exception {
        setUp();
        printProfileType();
        testLogin();
        deleteLdapUsers();
        testAuthenticate();
        deleteLdapUsers();
        testAuthenticateInactiveIdp();
        deleteLdapUsers();
        testAuthenticateFailure();
        deleteLdapUsers();
        validateOriginForNonLdapUser();
        deleteLdapUsers();
        validateOriginAndEmailForLdapUser();
        deleteLdapUsers();
        validateEmailMissingForLdapUser();
        deleteLdapUsers();
        testLdapScopes();
        deleteLdapUsers();
        testLdapScopesFromChainedAuth();
        deleteLdapUsers();
        testNestedLdapScopes();
        deleteLdapUsers();
        testNestedLdapGroupsMappedToScopes();
        deleteLdapUsers();
        testNestedLdapGroupsMappedToScopes2();
        deleteLdapUsers();
        testNestedLdapGroupsMappedToScopes3();
        deleteLdapUsers();
        testNestedLdapGroupsMappedToScopesWithDefaultScopes();
        deleteLdapUsers();
        testNestedLdapGroupsMappedToScopesWithDefaultScopes2();
        deleteLdapUsers();
        testNestedLdapGroupsMappedToScopesWithDefaultScopes3();
        deleteLdapUsers();
        testStopIfException();
        deleteLdapUsers();
    }

    public void printProfileType() throws Exception {
        assertEquals(ldapProfile, webApplicationContext.getBean("testLdapProfile"));
        assertEquals(ldapGroup, webApplicationContext.getBean("testLdapGroup"));
    }

    public void testLogin() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .param("username", "marissa")
                        .param("password", "koaladsada"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error=login_failure"));

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .param("username", "marissa2")
                        .param("password", "ldap"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    public void testAuthenticate() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
    }

    public void testAuthenticateInactiveIdp() throws Exception {
        IdentityProviderProvisioning provisioning = webApplicationContext.getBean(IdentityProviderProvisioning.class);
        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZone.getUaa().getId());
        try {
            ldapProvider.setActive(false);
            ldapProvider = provisioning.update(ldapProvider);
            String username = "marissa3";
            String password = "ldap3";
            performAuthentication(username, password, HttpStatus.UNAUTHORIZED);
        } finally {
            ldapProvider.setActive(true);
            provisioning.update(ldapProvider);
        }
    }

    public void testAuthenticateFailure() throws Exception {
        String username = "marissa3";
        String password = "ldapsadadasas";
        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .accept(MediaType.APPLICATION_JSON)
                .param("username",username)
                .param("password", password);
        mockMvc.perform(post)
            .andExpect(status().isUnauthorized());
    }

    public void validateOriginForNonLdapUser() throws Exception {
        String username = "marissa";
        String password = "koala";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa@test.org\""));
        assertEquals(Origin.UAA, getOrigin(username));
    }

    public void validateOriginAndEmailForLdapUser() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("marissa3@test.com",getEmail(username));
    }

    public void validateEmailMissingForLdapUser() throws Exception {
        String username = "marissa7";
        String password = "ldap7";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa7@user.from.ldap.cf\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("marissa7@user.from.ldap.cf",getEmail(username));
    }

    @Test
    public void validateCustomEmailForLdapUser() throws Exception {
        Assume.assumeTrue(ldapGroup.equals("ldap-groups-null.xml")); //this only pertains to auth
        mockEnvironment.setProperty("ldap.base.mailSubstitute", "{0}@ldaptest.org");
        setUp();
        String username = "marissa7";
        String password = "ldap7";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa7@ldaptest.org\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("marissa7@ldaptest.org",getEmail(username));

        ExtendedLdapUserMapper mapper = webApplicationContext.getBean(ExtendedLdapUserMapper.class);
        try {
            mapper.setMailSubstitute(null);
            assertNull(mapper.getMailSubstitute());
            mapper.setMailSubstitute("testing");
            fail("It should not be possible setting up an email substitute missing {0}");
        } catch (IllegalArgumentException x) {
        } catch (Exception x) { fail(x.getMessage()); }

        //null value should go back to default email
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("marissa3@test.com",getEmail(username));

        username = "marissa7";
        password = "ldap7";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa7@user.from.ldap.cf\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("marissa7@user.from.ldap.cf",getEmail(username));

        //non null value
        mapper.setMailSubstitute("user-{0}@testldap.org");
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"user-marissa7@testldap.org\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("user-marissa7@testldap.org",getEmail(username));

        //value not overridden
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("marissa3@test.com",getEmail(username));

        //value overridden
        mapper.setMailSubstituteOverridesLdap(true);
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"user-marissa3@testldap.org\""));
        assertEquals("ldap", getOrigin(username));
        assertEquals("user-marissa3@testldap.org",getEmail(username));
    }

    private String getOrigin(String username) {
        return jdbcTemplate.queryForObject("select origin from users where username='"+username+"'", String.class);
    }

    private String getEmail(String username) {
        return jdbcTemplate.queryForObject("select email from users where username='" + username + "' and origin='" + Origin.LDAP + "'", String.class);
    }

    private MvcResult performAuthentication(String username, String password) throws Exception {
        return performAuthentication(username, password, HttpStatus.OK);
    }

    private MvcResult performAuthentication(String username, String password, HttpStatus status) throws Exception {
        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .accept(MediaType.APPLICATION_JSON)
                .param("username", username)
                .param("password", password);

        return mockMvc.perform(post)
            .andExpect(status().is(status.value()))
            .andReturn();
    }


    public void testLdapScopes() throws Exception {
        if (!ldapGroup.equals("ldap-groups-as-scopes.xml")) {
            return;
        }
        AuthenticationManager manager = (AuthenticationManager)webApplicationContext.getBean("ldapAuthenticationManager");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa3","ldap3");
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        String[] list = new String[]{
            "uaa.admin",
            "cloud_controller.read"
        };
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));
    }

    public void testLdapScopesFromChainedAuth() throws Exception {
        if (!ldapGroup.equals("ldap-groups-as-scopes.xml")) {
            return;
        }
        AuthenticationManager manager = (AuthenticationManager)webApplicationContext.getBean("authzAuthenticationMgr");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa3","ldap3");
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        String[] list = new String[]{
            "uaa.admin",
            "password.write",
            "scim.userids",
            "approvals.me",
            "cloud_controller.write",
            "scim.me",
            "cloud_controller_service_permissions.read",
            "openid",
            "oauth.approvals",
            "uaa.user",
            "cloud_controller.read"
        };
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));
    }


    public void testNestedLdapScopes() throws Exception {
        if (!ldapGroup.equals("ldap-groups-as-scopes.xml")) {
            return;
        }
        AuthenticationManager manager = (AuthenticationManager)webApplicationContext.getBean("ldapAuthenticationManager");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa4","ldap4");
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        String[] list = new String[] {
                "test.read",
                "test.write",
            "test.everything",
        };
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));
    }

    public void doTestNestedLdapGroupsMappedToScopes(String username, String password, String[] expected) throws Exception {
        if (!ldapGroup.equals("ldap-groups-map-to-scopes.xml")) {
            return;
        }
        Set<String> externalGroupSet = new HashSet<String>();
        externalGroupSet.add("internal.superuser|cn=superusers,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.everything|cn=superusers,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.write|cn=operators,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.read|cn=developers,ou=scopes,dc=test,dc=com");
        AuthenticationManager manager = (AuthenticationManager)webApplicationContext.getBean("ldapAuthenticationManager");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,password);
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        String[] list = expected;
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));

    }

    public void testNestedLdapGroupsMappedToScopes() throws Exception {
        String[] list = new String[] {
            "internal.read",
            "internal.write",
            "internal.everything",
            "internal.superuser"
        };
        doTestNestedLdapGroupsMappedToScopes("marissa4","ldap4",list);
    }

    public void testNestedLdapGroupsMappedToScopes2() throws Exception {
        String[] list = new String[] {
            "internal.read",
            "internal.write",
        };
        doTestNestedLdapGroupsMappedToScopes("marissa5","ldap5",list);
    }

    public void testNestedLdapGroupsMappedToScopes3() throws Exception {
        String[] list = new String[] {
            "internal.read",
        };
        doTestNestedLdapGroupsMappedToScopes("marissa6","ldap6",list);
    }

    public void testNestedLdapGroupsMappedToScopesWithDefaultScopes() throws Exception {
        String username = "marissa4";
        String password = "ldap4";
        String[] list = new String[] {
            "internal.read",
            "internal.write",
            "internal.everything",
            "internal.superuser"
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username, password, list);
    }

    public void testNestedLdapGroupsMappedToScopesWithDefaultScopes2() throws Exception {

        String username = "marissa5";
        String password = "ldap5";
        String[] list = new String[] {
            "internal.read",
            "internal.write",
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username,password,list);
    }

    public void testNestedLdapGroupsMappedToScopesWithDefaultScopes3() throws Exception {

        String username = "marissa6";
        String password = "ldap6";
        String[] list = new String[] {
            "internal.read",
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username,password,list);
    }

    public void testStopIfException() throws Exception {
        if (ldapProfile.equals("ldap-simple-bind.xml") && ldapGroup.equals("ldap-groups-null.xml")) {
            ScimUser user = new ScimUser();
            user.setUserName("user@example.com");
            user.addEmail("user@example.com");
            user = uDB.createUser(user, "n1cel0ngp455w0rd");
            assertNotNull(user.getId());
            performAuthentication("user@example.com", "n1cel0ngp455w0rd", HttpStatus.OK);

            AuthzAuthenticationManager authzAuthenticationManager = webApplicationContext.getBean(AuthzAuthenticationManager.class);
            authzAuthenticationManager.setAllowUnverifiedUsers(false);
            performAuthentication("user@example.com", "n1cel0ngp455w0rd", HttpStatus.FORBIDDEN);
        }
    }

    public void doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(String username, String password, String[] expected) throws Exception {
        if (!ldapGroup.equals("ldap-groups-map-to-scopes.xml")) {
            return;
        }
        Set<String> externalGroupSet = new HashSet<>();
        externalGroupSet.add("internal.superuser|cn=superusers,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.everything|cn=superusers,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.write|cn=operators,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.read|cn=developers,ou=scopes,dc=test,dc=com");
        AuthenticationManager manager = webApplicationContext.getBean(ChainedAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,password);
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        Set<String> defaultAuthorities = (Set<String>)webApplicationContext.getBean("defaultUserAuthorities");
        String[] list = expected;
        defaultAuthorities.addAll(Arrays.asList(list));
        list = defaultAuthorities.toArray(new String[0]);
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));
    }




    public String[] getAuthorities(Collection<? extends GrantedAuthority> authorities) {
        String[] result = new String[authorities!=null?authorities.size():0];
        if (result.length>0) {
            int index=0;
            for (GrantedAuthority a : authorities) {
                result[index++] = a.getAuthority();
            }
        }
        return result;
    }
}
