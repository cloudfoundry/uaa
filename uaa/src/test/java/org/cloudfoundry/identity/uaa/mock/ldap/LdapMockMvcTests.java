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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.manager.ChainedAuthenticationManager;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.server.ApacheDSContainer;
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(Parameterized.class)
public class LdapMockMvcTests {

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {"ldap-simple-bind.xml", "ldap-groups-null.xml"},
            {"ldap-simple-bind.xml", "ldap-groups-as-scopes.xml"},
            {"ldap-simple-bind.xml", "ldap-groups-map-to-scopes.xml"},
            {"ldap-search-and-bind.xml", "ldap-groups-null.xml"},
            {"ldap-search-and-bind.xml", "ldap-groups-as-scopes.xml"},
            {"ldap-search-and-bind.xml", "ldap-groups-map-to-scopes.xml"},
            {"ldap-search-and-compare.xml", "ldap-groups-null.xml"},
            {"ldap-search-and-compare.xml", "ldap-groups-as-scopes.xml"},
            {"ldap-search-and-compare.xml", "ldap-groups-map-to-scopes.xml"}
        });
    }

    private static ApacheDSContainer apacheDS;
    private static File tmpDir;
    @BeforeClass
    public static void startApacheDS() throws Exception {
        tmpDir = new File(System.getProperty("java.io.tmpdir")+"/apacheds/"+new RandomValueStringGenerator().generate());
        tmpDir.deleteOnExit();
        System.out.println(tmpDir);
        System.setProperty("ldap.base.url","ldap://localhost:33389");
        apacheDS = new ApacheDSContainer("dc=test,dc=com","classpath:ldap_init.ldif");
        apacheDS.setWorkingDirectory(tmpDir);
        apacheDS.setPort(33389);
        apacheDS.afterPropertiesSet();
        apacheDS.start();
    }

    @AfterClass
    public static void stopApacheDS() {
        apacheDS.stop();

    }



    XmlWebApplicationContext webApplicationContext;

    MockMvc mockMvc;
    TestClient testClient;
    JdbcTemplate jdbcTemplate;
    JdbcScimGroupProvisioning gDB;
    ScimGroupExternalMembershipManager eDB;
    ScimExternalGroupBootstrap bootstrap;

    private String ldapProfile;
    private String ldapGroup;

    public LdapMockMvcTests(String ldapProfile, String ldapGroup) {
        this.ldapGroup = ldapGroup;
        this.ldapProfile = ldapProfile;
    }

    public void setUp() throws Exception {
        System.setProperty("ldap.profile.file", "ldap/"+ldapProfile);
        System.setProperty("ldap.profile.groups.file", "ldap/"+ldapGroup);
        System.setProperty("ldap.group.maxSearchDepth", "10");

        webApplicationContext = new XmlWebApplicationContext();
        MockServletContext servletContext = new MockServletContext();
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        servletConfig.addInitParameter("environmentConfigDefaults", "uaa.yml");
        webApplicationContext.setServletContext(servletContext);
        webApplicationContext.setServletConfig(servletConfig);
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();

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
        eDB = new JdbcScimGroupExternalMembershipManager(jdbcTemplate, pagingListFactory);
        ((JdbcScimGroupExternalMembershipManager) eDB).setScimGroupProvisioning(gDB);

        try {
            gDB.create(new ScimGroup("internal.read"));
            gDB.create(new ScimGroup("internal.write"));
            gDB.create(new ScimGroup("internal.everything"));
        }catch (ScimResourceAlreadyExistsException x) {
        }

        bootstrap = new ScimExternalGroupBootstrap(gDB, eDB);
    }

    @After
    public void tearDown() throws Exception {
        System.clearProperty("ldap.profile.file");
        if (webApplicationContext!=null) {
            webApplicationContext.destroy();
        }
    }

    @Test
    public void printProfileType() throws Exception {
        setUp();
        assertEquals(ldapProfile, webApplicationContext.getBean("testLdapProfile"));
    }

    @Test
    public void testLogin() throws Exception {

        setUp();
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .param("username", "marissa")
                        .param("password", "koaladsada"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error=true"));

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .param("username", "marissa2")
                        .param("password", "ldap"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    public void testAuthenticate() throws Exception {
        setUp();
        String username = "marissa3";
        String password = "ldap3";

        MockHttpServletRequestBuilder post =
            post("/authenticate")
            .accept(MediaType.APPLICATION_JSON)
            .param("username", username)
            .param("password", password);

        MvcResult result = mockMvc.perform(post)
            .andExpect(status().isOk())
            .andReturn();

        assertEquals("{\"username\":\"" + username + "\"}", result.getResponse().getContentAsString());
    }

    @Test
    public void testAuthenticateFailure() throws Exception {
        setUp();
        String username = "marissa3";
        String password = "ldapsadadasas";

        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .accept(MediaType.APPLICATION_JSON)
                .param("username",username)
                .param("password",password);

        mockMvc.perform(post)
            .andExpect(status().isUnauthorized());

    }

    @Test
    public void validateOriginForNonLdapUser() throws Exception {
        setUp();
        String username = "marissa";
        String password = "koala";

        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .accept(MediaType.APPLICATION_JSON)
                .param("username", username)
                .param("password", password);

        MvcResult result = mockMvc.perform(post)
            .andExpect(status().isOk())
            .andReturn();

        assertEquals("{\"username\":\"" + username + "\"}", result.getResponse().getContentAsString());

        String origin = jdbcTemplate.queryForObject("select origin from users where username='marissa'", String.class);
        assertEquals(Origin.UAA, origin);
    }

    @Test
    public void validateOriginAndEmailForLdapUser() throws Exception {
        setUp();
        String username = "marissa3";
        String password = "ldap3";

        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .accept(MediaType.APPLICATION_JSON)
                .param("username", username)
                .param("password", password);

        MvcResult result = mockMvc.perform(post)
            .andExpect(status().isOk())
            .andReturn();

        assertEquals("{\"username\":\"" + username + "\"}", result.getResponse().getContentAsString());

        String origin = jdbcTemplate.queryForObject("select origin from users where username='marissa3'", String.class);
        assertEquals("ldap", origin);
        String email = jdbcTemplate.queryForObject("select email from users where username='marissa3' and origin='ldap'", String.class);
        assertEquals("marissa3@test.com", email);
    }

    @Test
    public void validateEmailMissingForLdapUser() throws Exception {
        setUp();
        String username = "marissa7";
        String password = "ldap7";

        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .accept(MediaType.APPLICATION_JSON)
                .param("username", username)
                .param("password", password);

        MvcResult result = mockMvc.perform(post)
            .andExpect(status().isOk())
            .andReturn();

        assertEquals("{\"username\":\"" + username + "\"}", result.getResponse().getContentAsString());

        String origin = jdbcTemplate.queryForObject("select origin from users where username='marissa7'", String.class);
        assertEquals("ldap", origin);
        String email = jdbcTemplate.queryForObject("select email from users where username='marissa7' and origin='ldap'", String.class);
        assertEquals("marissa7@user.from.ldap.cf", email);
    }

    @Test
    public void testLdapScopes() throws Exception {
        Assume.assumeTrue(ldapGroup.equals("ldap-groups-as-scopes.xml"));
        setUp();
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

    @Test
    public void testLdapScopesFromChainedAuth() throws Exception {
        Assume.assumeTrue(ldapGroup.equals("ldap-groups-as-scopes.xml"));
        setUp();
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


    @Test
    public void testNestedLdapScopes() throws Exception {
        Assume.assumeTrue(ldapGroup.equals("ldap-groups-as-scopes.xml"));
        setUp();
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
        Assume.assumeTrue(ldapGroup.equals("ldap-groups-map-to-scopes.xml"));
        setUp();
        Set<String> externalGroupSet = new HashSet<String>();
        externalGroupSet.add("internal.everything|cn=superusers,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.write|cn=operators,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.read|cn=developers,ou=scopes,dc=test,dc=com");
        bootstrap.setExternalGroupMap(externalGroupSet);
        bootstrap.afterPropertiesSet();

        AuthenticationManager manager = (AuthenticationManager)webApplicationContext.getBean("ldapAuthenticationManager");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,password);
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        String[] list = expected;
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(auth.getAuthorities())));

    }

    @Test
    public void testNestedLdapGroupsMappedToScopes() throws Exception {
        String[] list = new String[] {
            "internal.read",
            "internal.write",
            "internal.everything",
        };
        doTestNestedLdapGroupsMappedToScopes("marissa4","ldap4",list);
    }

    @Test
    public void testNestedLdapGroupsMappedToScopes2() throws Exception {
        String[] list = new String[] {
            "internal.read",
            "internal.write",
        };
        doTestNestedLdapGroupsMappedToScopes("marissa5","ldap5",list);
    }

    @Test
    public void testNestedLdapGroupsMappedToScopes3() throws Exception {
        String[] list = new String[] {
            "internal.read",
        };
        doTestNestedLdapGroupsMappedToScopes("marissa6","ldap6",list);
    }

    @Test
    public void testNestedLdapGroupsMappedToScopesWithDefaultScopes() throws Exception {

        String username = "marissa4";
        String password = "ldap4";
        String[] list = new String[] {
            "internal.read",
            "internal.write",
            "internal.everything",
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username,password,list);
    }

    @Test
    public void testNestedLdapGroupsMappedToScopesWithDefaultScopes2() throws Exception {

        String username = "marissa5";
        String password = "ldap5";
        String[] list = new String[] {
            "internal.read",
            "internal.write",
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username,password,list);
    }

    @Test
    public void testNestedLdapGroupsMappedToScopesWithDefaultScopes3() throws Exception {

        String username = "marissa6";
        String password = "ldap6";
        String[] list = new String[] {
            "internal.read",
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username,password,list);
    }

    public void doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(String username, String password, String[] expected) throws Exception {
        Assume.assumeTrue(ldapGroup.equals("ldap-groups-map-to-scopes.xml"));
        setUp();
        Set<String> externalGroupSet = new HashSet<>();
        externalGroupSet.add("internal.everything|cn=superusers,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.write|cn=operators,ou=scopes,dc=test,dc=com");
        externalGroupSet.add("internal.read|cn=developers,ou=scopes,dc=test,dc=com");
        bootstrap.setExternalGroupMap(externalGroupSet);
        bootstrap.afterPropertiesSet();

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
