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
package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.ApacheDSHelper;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.ZoneScimInviteData;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest.UsernamePasswordAuthentication;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserMapper;
import org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.flywaydb.core.Flyway;
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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.servlet.http.HttpSession;
import java.io.File;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import static java.util.Collections.EMPTY_LIST;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_ATTRIBUTE_MAPPINGS;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
//            {"ldap-simple-bind.xml", "ldap-groups-null.xml", "ldap://localhost:33389"},
//            {"ldap-simple-bind.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389"},
//            {"ldap-simple-bind.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389"},
//            {"ldap-simple-bind.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636"},
//            {"ldap-search-and-bind.xml", "ldap-groups-null.xml", "ldap://localhost:33389"},
//            {"ldap-search-and-bind.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389"},
            {"ldap-search-and-bind.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389"},
//            {"ldap-search-and-bind.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636"},
//            {"ldap-search-and-compare.xml", "ldap-groups-null.xml", "ldap://localhost:33389"},
//            {"ldap-search-and-compare.xml", "ldap-groups-as-scopes.xml", "ldap://localhost:33389"},
//            {"ldap-search-and-compare.xml", "ldap-groups-map-to-scopes.xml", "ldap://localhost:33389"},
            {"ldap-search-and-compare.xml", "ldap-groups-as-scopes.xml", "ldaps://localhost:33636"},
//            {"ldap-search-and-compare.xml", "ldap-groups-map-to-scopes.xml", "ldaps://localhost:33636"}
        });
    }

    private static ApacheDsSSLContainer apacheDS;
    private static ApacheDsSSLContainer apacheDS2;
    private static File tmpDir;

    @AfterClass
    public static void afterClass() {
        apacheDS.stop();
    }

    @BeforeClass
    public static void startApacheDS() throws Exception {
        apacheDS = ApacheDSHelper.start();
    }

    XmlWebApplicationContext mainContext;

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

        mainContext = new XmlWebApplicationContext();
        mainContext.setEnvironment(mockEnvironment);
        mainContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(mainContext, "uaa.yml,login.yml");
        mainContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        mainContext.getEnvironment().addActiveProfile("default");
        mainContext.getEnvironment().addActiveProfile(LDAP);
        mainContext.refresh();

        List<String> profiles = Arrays.asList(mainContext.getEnvironment().getActiveProfiles());
        Assume.assumeTrue(profiles.contains(LDAP));

        //we need to reinitialize the context if we change the ldap.profile.file property
        FilterChainProxy springSecurityFilterChain = mainContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(mainContext).addFilter(springSecurityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);
        jdbcTemplate = mainContext.getBean(JdbcTemplate.class);
        LimitSqlAdapter limitSqlAdapter = mainContext.getBean(LimitSqlAdapter.class);
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter);
        gDB = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);
        uDB = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory);
        userDatabase = mainContext.getBean(UaaUserDatabase.class);
    }

    @After
    public void tearDown() throws Exception {
        System.clearProperty("ldap.profile.file");
        System.clearProperty("ldap.base.mailSubstitute");
        if (mainContext!=null) {
            Flyway flyway = mainContext.getBean(Flyway.class);
            flyway.clean();
            mainContext.destroy();
        }
    }

    private void deleteLdapUsers() {
        jdbcTemplate.update("delete from users where origin='" + LDAP + "'");
    }

    public void acceptInvitation_for_ldap_user_whose_username_is_not_email() throws Exception {
        setUp();
        mainContext.getBean(JdbcTemplate.class).update("delete from expiring_code_store");
        String REDIRECT_URI = "http://invitation.redirect.test";
        String clientId = new RandomValueStringGenerator().generate();
        String email = "marissa2@test.com";
        mainContext.getBean(JdbcTemplate.class).update("DELETE FROM users WHERE email=?", email);
        ZoneScimInviteData zone = utils().createZoneForInvites(mockMvc, mainContext, clientId, REDIRECT_URI);
        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldap://localhost:33389/",
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
                true);
        definition.setEmailDomain(Arrays.asList("test.com"));
        utils().createIdentityProvider(mockMvc, zone.getZone(), LDAP, definition);

        URL url = utils().inviteUser(mainContext, mockMvc, email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), LDAP, REDIRECT_URI);
        String code = utils().extractInvitationCode(url.toString());

        String userInfoOrigin = mainContext.getBean(JdbcTemplate.class).queryForObject("select origin from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String userInfoId = mainContext.getBean(JdbcTemplate.class).queryForObject("select id from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        assertEquals(LDAP, userInfoOrigin);

        ResultActions actions = mockMvc.perform(get("/invitations/accept")
                        .param("code", code)
                        .accept(MediaType.TEXT_HTML)
                        .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
        );
        MvcResult result = actions.andExpect(status().isOk())
                .andExpect(content().string(containsString("Link your account")))
                .andExpect(content().string(containsString("Email: " + email)))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andExpect(content().string(containsString("<input type=\"submit\" value=\"Sign in\" class=\"island-button\" />")))
                .andReturn();

        code = mainContext.getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        mockMvc.perform(post("/invitations/accept_enterprise.do")
                .session(session)
                .param("enterprise_username", "marissa2")
                .param("enterprise_password", LDAP)
                .param("enterprise_email", "email")
                .param("code", code)
                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
                .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(REDIRECT_URI))
                .andReturn();

        String newUserInfoId = mainContext.getBean(JdbcTemplate.class).queryForObject("select id from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String newUserInfoOrigin = mainContext.getBean(JdbcTemplate.class).queryForObject("select origin from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String newUserInfoUsername = mainContext.getBean(JdbcTemplate.class).queryForObject("select username from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        assertEquals(LDAP, newUserInfoOrigin);
        assertEquals("marissa2", newUserInfoUsername);
        //ensure that a new user wasn't created
        assertEquals(userInfoId, newUserInfoId);


        //email mismatch
        mainContext.getBean(JdbcTemplate.class).update("delete from expiring_code_store");
        email = "different@test.com";
        url = utils().inviteUser(mainContext, mockMvc, email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), LDAP, REDIRECT_URI);
        code = utils().extractInvitationCode(url.toString());

        actions = mockMvc.perform(get("/invitations/accept")
                        .param("code", code)
                        .accept(MediaType.TEXT_HTML)
                        .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
        );
        result = actions.andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andReturn();

        code = mainContext.getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);

        session = (MockHttpSession) result.getRequest().getSession(false);
        mockMvc.perform(post("/invitations/accept_enterprise.do")
                .session(session)
                .param("enterprise_username", "marissa2")
                .param("enterprise_password", LDAP)
                .param("enterprise_email", "email")
                .param("code", code)
                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
                .with(csrf()))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().string(containsString("The authenticated email does not match the invited email. Please log in using a different account.")))
                .andReturn();
        boolean userVerified = Boolean.parseBoolean(mainContext.getBean(JdbcTemplate.class).queryForObject("select verified from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId()));
        assertFalse(userVerified);

    }

    @Test
    public void test_external_groups_whitelist() throws Exception {
        Assume.assumeThat("ldap-groups-map-to-scopes.xml, ldap-groups-as-scopes.xml", StringContains.containsString(ldapGroup));
        setUp();
        IdentityProviderProvisioning idpProvisioning = mainContext.getBean(IdentityProviderProvisioning.class);
        IdentityProvider<LdapIdentityProviderDefinition> idp = idpProvisioning.retrieveByOrigin(LDAP, IdentityZone.getUaa().getId());
        LdapIdentityProviderDefinition def = idp.getConfig();
        def.addWhiteListedGroup("admins");
        def.addWhiteListedGroup("thirdmarissa");
        idp.setConfig(def);
        idpProvisioning.update(idp);
        AuthenticationManager manager = mainContext.getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa3", "ldap3");
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        assertTrue(auth instanceof UaaAuthentication);
        UaaAuthentication uaaAuth = (UaaAuthentication) auth;
        Set<String> externalGroups = uaaAuth.getExternalGroups();
        assertNotNull(externalGroups);
        assertEquals(2, externalGroups.size());
        assertThat(externalGroups, containsInAnyOrder("admins", "thirdmarissa"));

        //default whitelist
        def.setExternalGroupsWhitelist(EMPTY_LIST);
        idp.setConfig(def);
        idpProvisioning.update(idp);
        auth = manager.authenticate(token);
        assertNotNull(auth);
        assertTrue(auth instanceof UaaAuthentication);
        uaaAuth = (UaaAuthentication) auth;
        externalGroups = uaaAuth.getExternalGroups();
        assertNotNull(externalGroups);
        assertEquals(0, externalGroups.size());

    }

    @Test
    public void testCustomUserAttributes() throws Exception {
        Assume.assumeThat("ldap-groups-map-to-scopes.xml, ldap-groups-as-scopes.xml", StringContains.containsString(ldapGroup));

        final String MANAGER = "uaaManager";
        final String MANAGERS = "managers";
        final String DENVER_CO = "Denver,CO";
        final String COST_CENTER = "costCenter";
        final String COST_CENTERS = COST_CENTER+"s";
        final String JOHN_THE_SLOTH = "John the Sloth";
        final String KARI_THE_ANT_EATER = "Kari the Ant Eater";
        final String FIRST_NAME = "first_name";
        final String FAMILY_NAME = "family_name";
        final String PHONE_NUMBER = "phone_number";
        final String EMAIL = "email";


        createMockEnvironment();
        mockEnvironment.setProperty("ldap."+ ATTRIBUTE_MAPPINGS+".user.attribute."+MANAGERS, MANAGER);
        mockEnvironment.setProperty("ldap."+ATTRIBUTE_MAPPINGS+".user.attribute."+COST_CENTERS, COST_CENTER);

        //test to remap the user/person properties
        mockEnvironment.setProperty(LDAP_ATTRIBUTE_MAPPINGS+"."+FIRST_NAME, "sn");
        mockEnvironment.setProperty(LDAP_ATTRIBUTE_MAPPINGS+"."+PHONE_NUMBER, "givenname");
        mockEnvironment.setProperty(LDAP_ATTRIBUTE_MAPPINGS+"."+FAMILY_NAME, "telephonenumber");

        setUp();

        String username = "marissa9";
        String password = "ldap9";
        MvcResult result = performUiAuthentication(username, password, HttpStatus.FOUND);

        UaaAuthentication authentication = (UaaAuthentication) ((SecurityContext) result.getRequest().getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY)).getAuthentication();

        assertEquals("Expected two user attributes", 2, authentication.getUserAttributes().size());
        assertNotNull("Expected cost center attribute", authentication.getUserAttributes().get(COST_CENTERS));
        assertEquals(DENVER_CO, authentication.getUserAttributes().getFirst(COST_CENTERS));

        assertNotNull("Expected manager attribute", authentication.getUserAttributes().get(MANAGERS));
        assertEquals("Expected 2 manager attribute values", 2, authentication.getUserAttributes().get(MANAGERS).size());
        assertThat(authentication.getUserAttributes().get(MANAGERS), containsInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));

        assertEquals("8885550986", getFamilyName(username));
        assertEquals("Marissa", getPhoneNumber(username));
        assertEquals("Marissa9", getGivenName(username));
    }

    @Test
    public void testLdapConfigurationBeforeSave() throws Exception {
        Assume.assumeThat("ldap-search-and-bind.xml", StringContains.containsString(ldapProfile));
        Assume.assumeThat("ldap-groups-map-to-scopes.xml", StringContains.containsString(ldapGroup));

        setUp();
        String identityAccessToken = utils().getClientOAuthAccessToken(mockMvc, "identity", "identitysecret", "");
        String adminAccessToken = utils().getClientOAuthAccessToken(mockMvc, "admin", "adminsecret", "");
        IdentityZone zone = utils().createZoneUsingWebRequest(mockMvc, identityAccessToken);
        String zoneAdminToken = utils().getZoneAdminToken(mockMvc, adminAccessToken, zone.getId());

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
        provider.setOriginKey(LDAP);
        provider.setName("Test ldap provider");
        provider.setType(LDAP);
        provider.setConfig(definition);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getId());

        UsernamePasswordAuthentication token = new UsernamePasswordAuthentication("marissa2", LDAP);

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
        provider.setConfig(definition);
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
        provider.setConfig(definition);
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
        provider.setConfig(definition);
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

        ProcessLdapProperties processLdapProperties = getBean(ProcessLdapProperties.class);
        if (processLdapProperties.isLdapsUrl()) {
            token = new UsernamePasswordAuthentication("marissa2", LDAP);

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
            provider.setConfig(definition);
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
            provider.setConfig(definition);
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

    public void testLoginInNonDefaultZone() throws Exception {
        if (!(ldapProfile.contains("ldap-search-and-bind.xml") &&
            ldapGroup.contains("ldap-groups-map-to-scopes.xml"))) {
            return;
        }

        setUp();
        String identityAccessToken = utils().getClientOAuthAccessToken(mockMvc, "identity", "identitysecret", "");
        String adminAccessToken = utils().getClientOAuthAccessToken(mockMvc, "admin", "adminsecret", "");
        IdentityZone zone = utils().createZoneUsingWebRequest(mockMvc, identityAccessToken);
        String zoneAdminToken = utils().getZoneAdminToken(mockMvc, adminAccessToken, zone.getId());

        mockMvc.perform(get("/login")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        //IDP not yet created
        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(cookieCsrf())
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
            .param("username", "marissa2")
            .param("password", LDAP))
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
        provider.setOriginKey(LDAP);
        provider.setName("Test ldap provider");
        provider.setType(LDAP);
        provider.setConfig(definition);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getId());
        provider = utils().createIdpUsingWebRequest(mockMvc, zone.getId(), zoneAdminToken, provider, status().isCreated());

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(cookieCsrf())
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
            .param("username", "marissa2")
            .param("password", LDAP))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone);
        UaaUser user = userDatabase.retrieveUserByName("marissa2", LDAP);
        IdentityZoneHolder.clear();
        assertNotNull(user);
        assertEquals(LDAP, user.getOrigin());
        assertEquals(zone.getId(), user.getZoneId());

        provider.setActive(false);
        utils().createIdpUsingWebRequest(mockMvc, zone.getId(), zoneAdminToken, provider, status().isOk(), true);
        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(cookieCsrf())
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
            .param("username", "marissa2")
            .param("password", LDAP))
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
        provider.setConfig(definition);
        utils().createIdpUsingWebRequest(mockMvc, zone.getId(), zoneAdminToken, provider, status().isOk(), true);

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(cookieCsrf())
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost"))
            .param("username", "marissa2")
            .param("password", LDAP))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone);
        user = userDatabase.retrieveUserByName("marissa2", LDAP);
        IdentityZoneHolder.clear();
        assertNotNull(user);
        assertEquals(LDAP, user.getOrigin());
        assertEquals(zone.getId(), user.getZoneId());
        assertEquals("marissa2@ldaptest.com", user.getEmail());
    }

    @Test
    public void testLogin_partial_result_exception_on_group_search() throws Exception {
        Assume.assumeThat("ldap-search-and-bind.xml", StringContains.containsString(ldapProfile));
        Assume.assumeThat("ldap-groups-map-to-scopes.xml", StringContains.containsString(ldapGroup));

        setUp();
        String identityAccessToken = utils().getClientOAuthAccessToken(mockMvc, "identity", "identitysecret", "");
        String adminAccessToken = utils().getClientOAuthAccessToken(mockMvc, "admin", "adminsecret", "");
        IdentityZone zone = utils().createZoneUsingWebRequest(mockMvc, identityAccessToken);
        String zoneAdminToken = utils().getZoneAdminToken(mockMvc, adminAccessToken, zone.getId());

        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:33389",
            "cn=admin,ou=Users,dc=test,dc=com",
            "adminsecret",
            "dc=test,dc=com",
            "cn={0}",
            "dc=test,dc=com",
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
        provider.setOriginKey(LDAP);
        provider.setName("Test ldap provider");
        provider.setType(LDAP);
        provider.setConfig(definition);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getId());
        provider = utils().createIdpUsingWebRequest(mockMvc, zone.getId(), zoneAdminToken, provider, status().isCreated());

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                            .with(cookieCsrf())
                            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain()+".localhost"))
                            .param("username", "marissa8")
                            .param("password", "ldap8"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone);
        UaaUser user = userDatabase.retrieveUserByName("marissa8", LDAP);
        IdentityZoneHolder.clear();
        assertNotNull(user);
        assertEquals(LDAP, user.getOrigin());
        assertEquals(zone.getId(), user.getZoneId());

    }


    @Test
    public void runLdapTestblock() throws Exception {
        setUp();
        printProfileType();
        testLogin();
        deleteLdapUsers();
        testAuthenticate();
        deleteLdapUsers();
        testExtendedAttributes();
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
        acceptInvitation_for_ldap_user_whose_username_is_not_email();
        deleteLdapUsers();
        testLoginInNonDefaultZone();
        deleteLdapUsers();
        testAuthenticateWithUTF8Characters();
        deleteLdapUsers();
    }

    public Object getBean(String name) {
        IdentityProviderProvisioning provisioning = mainContext.getBean(IdentityProviderProvisioning.class);
        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(LDAP, IdentityZoneHolder.get().getId());
        DynamicZoneAwareAuthenticationManager zm = mainContext.getBean(DynamicZoneAwareAuthenticationManager.class);
        zm.getLdapAuthenticationManager(IdentityZone.getUaa(), ldapProvider).getLdapAuthenticationManager();
        return zm.getLdapAuthenticationManager(IdentityZone.getUaa(), ldapProvider).getContext().getBean(name);
    }

    public <T> T getBean(Class<T> clazz) {
        IdentityProviderProvisioning provisioning = mainContext.getBean(IdentityProviderProvisioning.class);
        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(LDAP, IdentityZoneHolder.get().getId());
        DynamicZoneAwareAuthenticationManager zm = mainContext.getBean(DynamicZoneAwareAuthenticationManager.class);
        zm.getLdapAuthenticationManager(IdentityZone.getUaa(), ldapProvider).getLdapAuthenticationManager();
        return zm.getLdapAuthenticationManager(IdentityZone.getUaa(), ldapProvider).getContext().getBean(clazz);
    }

    public void printProfileType() throws Exception {
        assertEquals(ldapProfile, getBean("testLdapProfile"));
        assertEquals(ldapGroup, getBean("testLdapGroup"));
    }

    public void testLogin() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(cookieCsrf())
            .param("username", "marissa")
            .param("password", "koaladsada"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?error=login_failure"));

        testSuccessfulLogin();
    }

    @Test
    public void testTwoLdapServers() throws Exception {
        int port = 43390 + new Random(System.currentTimeMillis()).nextInt(300);
        int sslPort = port + 300;
        apacheDS2 = ApacheDSHelper.start(port,sslPort);
        String originalUrl = ldapBaseUrl;
        if (ldapBaseUrl.contains("ldap://")) {
            ldapBaseUrl = ldapBaseUrl + " ldap://localhost:"+port;
        } else {
            ldapBaseUrl = ldapBaseUrl + " ldaps://localhost:"+sslPort;
        }
        try {
            setUp();
            testSuccessfulLogin();
            apacheDS.stop();
            testSuccessfulLogin();
            apacheDS2.stop();
        } finally {
            ldapBaseUrl = originalUrl;
            if (apacheDS.isRunning()) {
                apacheDS.stop();
            }
            apacheDS = null;
            if (apacheDS2.isRunning()) {
                apacheDS2.stop();
            }
            apacheDS2 = null;
            apacheDS = ApacheDSHelper.start();
        }
    }

    protected void testSuccessfulLogin() throws Exception {

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
            .with(cookieCsrf())
            .param("username", "marissa2")
            .param("password", LDAP))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));
    }

    protected void testAuthenticateWithUTF8Characters() throws Exception {
        String username = "\u7433\u8D3A";
        DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager = mainContext.getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, "koala");
        Authentication auth = zoneAwareAuthenticationManager.authenticate(token);
        assertTrue(auth.isAuthenticated());

        HttpSession session = mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                            .with(cookieCsrf())
                            .param("username", username)
                            .param("password", "koala"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
        .andReturn().getRequest().getSession(false);
        assertNotNull(session);
        assertNotNull(session.getAttribute(SPRING_SECURITY_CONTEXT_KEY));
        Authentication authentication = ((SecurityContext)session.getAttribute(SPRING_SECURITY_CONTEXT_KEY)).getAuthentication();
        assertNotNull(authentication);
        assertTrue(authentication.isAuthenticated());
    }

    public void testAuthenticate() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
    }

    public void testExtendedAttributes() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
        assertEquals("Marissa", getGivenName(username));
        assertEquals("Lastnamerton", getFamilyName(username));
        assertEquals("8885550986", getPhoneNumber(username));
    }


    public void testAuthenticateInactiveIdp() throws Exception {
        IdentityProviderProvisioning provisioning = mainContext.getBean(IdentityProviderProvisioning.class);
        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(LDAP, IdentityZone.getUaa().getId());
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
                .param("username", username)
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
        assertEquals(OriginKeys.UAA, getOrigin(username));
    }

    public void validateOriginAndEmailForLdapUser() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
        assertEquals(LDAP, getOrigin(username));
        assertEquals("marissa3@test.com",getEmail(username));
    }

    public void validateEmailMissingForLdapUser() throws Exception {
        String username = "marissa7";
        String password = "ldap7";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa7@user.from.ldap.cf\""));
        assertEquals(LDAP, getOrigin(username));
        assertEquals("marissa7@user.from.ldap.cf", getEmail(username));
    }

    @Test
    public void validateLoginAsInvitedUserWithoutClickingInviteLink() throws Exception {
        setUp();
        assertNull(userDatabase.retrieveUserByEmail("marissa7@user.from.ldap.cf", LDAP));

        ScimUser user = new ScimUser(null, "marissa7@user.from.ldap.cf", "Marissa", "Seven");
        user.setPrimaryEmail("marissa7@user.from.ldap.cf");
        user.setOrigin(LDAP);
        ScimUser createdUser = uDB.createUser(user, "");

        performUiAuthentication("marissa7", "ldap7", HttpStatus.FOUND);

        UaaUser authedUser = userDatabase.retrieveUserByEmail("marissa7@user.from.ldap.cf", LDAP);
        assertEquals(createdUser.getId(), authedUser.getId());
        List<ScimUser> scimUserList = uDB.query(String.format("origin eq '%s'", LDAP));
        assertEquals(1, scimUserList.size());
        assertEquals("marissa7", authedUser.getUsername());
    }

    @Test
    public void validateCustomEmailForLdapUser() throws Exception {
        Assume.assumeThat("ldap-groups-map-to-scopes.xml", StringContains.containsString(ldapGroup));
        mockEnvironment.setProperty("ldap.base.mailSubstitute", "{0}@ldaptest.org");
        setUp();
        String username = "marissa7";
        String password = "ldap7";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa7@ldaptest.org\""));
        assertEquals(LDAP, getOrigin(username));
        assertEquals("marissa7@ldaptest.org",getEmail(username));

        ExtendedLdapUserMapper mapper = getBean(ExtendedLdapUserMapper.class);
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
        assertEquals(LDAP, getOrigin(username));
        assertEquals("marissa3@test.com",getEmail(username));

        username = "marissa7";
        password = "ldap7";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa7@user.from.ldap.cf\""));
        assertEquals(LDAP, getOrigin(username));
        assertEquals("marissa7@user.from.ldap.cf",getEmail(username));

        //non null value
        mapper.setMailSubstitute("user-{0}@testldap.org");
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"user-marissa7@testldap.org\""));
        assertEquals(LDAP, getOrigin(username));
        assertEquals("user-marissa7@testldap.org",getEmail(username));

        //value not overridden
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"marissa3@test.com\""));
        assertEquals(LDAP, getOrigin(username));
        assertEquals("marissa3@test.com",getEmail(username));

        //value overridden
        mapper.setMailSubstituteOverridesLdap(true);
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString(), containsString("\"username\":\"" + username + "\""));
        assertThat(result.getResponse().getContentAsString(), containsString("\"email\":\"user-marissa3@testldap.org\""));
        assertEquals(LDAP, getOrigin(username));
        assertEquals("user-marissa3@testldap.org",getEmail(username));
    }

    private String getOrigin(String username) {
        return jdbcTemplate.queryForObject("select origin from users where username='"+username+"'", String.class);
    }

    private String getEmail(String username) {
        return jdbcTemplate.queryForObject("select email from users where username='" + username + "' and origin='" + LDAP + "'", String.class);
    }

    private String getGivenName(String username) {
        return jdbcTemplate.queryForObject("select givenname from users where username='" + username + "' and origin='" + LDAP + "'", String.class);
    }

    private String getFamilyName(String username) {
        return jdbcTemplate.queryForObject("select familyname from users where username='" + username + "' and origin='" + LDAP + "'", String.class);
    }

    private String getPhoneNumber(String username) {
        return jdbcTemplate.queryForObject("select phonenumber from users where username='" + username + "' and origin='" + LDAP + "'", String.class);
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

    private MvcResult performUiAuthentication(String username, String password, HttpStatus status) throws Exception {
        MockHttpServletRequestBuilder post =
            post("/login.do")
                .with(cookieCsrf())
                .accept(MediaType.TEXT_HTML)
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
        AuthenticationManager manager = (AuthenticationManager)getBean("ldapAuthenticationManager");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa3","ldap3");
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        String[] list = new String[]{
            "uaa.admin",
            "cloud_controller.read",
            "thirdmarissa"
        };
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));
    }

    public void testLdapScopesFromChainedAuth() throws Exception {
        if (!ldapGroup.equals("ldap-groups-as-scopes.xml")) {
            return;
        }
        AuthenticationManager manager = (AuthenticationManager)mainContext.getBean("zoneAwareAuthzAuthenticationManager");
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
            "profile",
            "roles",
            "oauth.approvals",
            "uaa.user",
            "cloud_controller.read",
            "user_attributes",
            UaaTokenServices.UAA_REFRESH_TOKEN,
            "thirdmarissa"
        };
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));
    }


    public void testNestedLdapScopes() throws Exception {
        if (!ldapGroup.equals("ldap-groups-as-scopes.xml")) {
            return;
        }
        Set<String> defaultAuthorities = new HashSet((Set<String>)mainContext.getBean("defaultUserAuthorities"));
        AuthenticationManager manager = mainContext.getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa4","ldap4");
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        defaultAuthorities.addAll(Arrays.asList("test.read", "test.write", "test.everything"));
        assertThat(UaaStringUtils.getStringsFromAuthorities(auth.getAuthorities()), containsInAnyOrder(defaultAuthorities.toArray()));
    }

    public void doTestNestedLdapGroupsMappedToScopes(String username, String password, String[] expected) throws Exception {
        if (!ldapGroup.equals("ldap-groups-map-to-scopes.xml")) {
            return;
        }
        AuthenticationManager manager = mainContext.getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,password);
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);

        Set<String> defaultAuthorities = new HashSet((Set<String>)mainContext.getBean("defaultUserAuthorities"));
        for (String s : expected) {
            defaultAuthorities.add(s);
        }
        assertThat(UaaStringUtils.getStringsFromAuthorities(auth.getAuthorities()), containsInAnyOrder(defaultAuthorities.toArray()));
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

            AuthzAuthenticationManager authzAuthenticationManager = mainContext.getBean(AuthzAuthenticationManager.class);
            authzAuthenticationManager.setAllowUnverifiedUsers(false);
            performAuthentication("user@example.com", "n1cel0ngp455w0rd", HttpStatus.FORBIDDEN);
        }
    }

    public void doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(String username, String password, String[] expected) throws Exception {
        if (!ldapGroup.equals("ldap-groups-map-to-scopes.xml")) {
            return;
        }
        AuthenticationManager manager = mainContext.getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,password);
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        Set<String> defaultAuthorities = new HashSet((Set<String>)mainContext.getBean("defaultUserAuthorities"));
        defaultAuthorities.addAll(Arrays.asList(expected));

        assertThat(UaaStringUtils.getStringsFromAuthorities(auth.getAuthorities()), containsInAnyOrder(defaultAuthorities.toArray()));
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
