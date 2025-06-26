package org.cloudfoundry.identity.uaa.mock.ldap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.InterceptingLogger;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.InMemoryLdapServer;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import jakarta.servlet.http.HttpSession;
import java.io.File;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createClient;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DefaultTestContext
@ExtendWith(InMemoryLdapServer.LdapTrustStoreExtension.class)
public abstract class AbstractLdapMockMvcTest {
    private static final String REDIRECT_URI = "http://invitation.redirect.test";
    static final File KEYSTORE;

    static {
        ClassLoader classLoader = LdapSimpleBindTest.class.getClassLoader();
        KEYSTORE = new File(classLoader.getResource("certs/valid-self-signed-ldap-cert.jks").getFile());
    }

    private String ldapProfile;
    private String ldapGroup;
    private String tlsConfig;

    private String host;
    private ApplicationListener<AbstractUaaEvent> listener;
    private MockMvcUtils.ZoneScimInviteData zone;
    private IdentityProvider<LdapIdentityProviderDefinition> provider;

    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    private LoggingAuditService loggingAuditService;
    private InterceptingLogger testLogger;
    private Logger originalAuditServiceLogger;

    private WebApplicationContext getWebApplicationContext() {
        return webApplicationContext;
    }

    MockMvc getMockMvc() {
        return mockMvc;
    }

    protected abstract void ensureLdapServerIsRunning();

    protected abstract void stopLdapServer();

    protected abstract String getLdapUrl();

    // Called by child classes. Allows this abstract parent class to act like a parameterized test.
    AbstractLdapMockMvcTest(String ldapProfile, String ldapGroup, String tlsConfig) {
        this.ldapProfile = ldapProfile;
        this.ldapGroup = ldapGroup;
        this.tlsConfig = tlsConfig;
    }

    @BeforeEach
    void setUp(@Autowired WebApplicationContext webApplicationContext,
               @Autowired MockMvc mockMvc,
               @Autowired ConfigurableApplicationContext configurableApplicationContext,
               @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning,
               @Autowired LoggingAuditService loggingAuditService) throws Exception {
        this.webApplicationContext = webApplicationContext;
        this.mockMvc = mockMvc;
        this.jdbcScimUserProvisioning = jdbcScimUserProvisioning;
        this.loggingAuditService = loggingAuditService;

        String userId = new RandomValueStringGenerator().generate().toLowerCase();
        zone = MockMvcUtils.createZoneForInvites(getMockMvc(), getWebApplicationContext(), userId, REDIRECT_URI, IdentityZoneHolder.getCurrentZoneId());

        try {
            ensureLdapServerIsRunning();

            LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
            definition.setLdapProfileFile("ldap/" + ldapProfile);
            definition.setLdapGroupFile("ldap/" + ldapGroup);
            definition.setMaxGroupSearchDepth(10);
            definition.setBaseUrl(getLdapUrl());
            definition.setBindUserDn("cn=admin,ou=Users,dc=test,dc=com");
            definition.setBindPassword("adminsecret");
            definition.setSkipSSLVerification(false);
            definition.setTlsConfiguration(tlsConfig);
            definition.setMailAttributeName("mail");
            definition.setReferral("ignore");

            provider = MockMvcUtils.createIdentityProvider(getMockMvc(), zone.getZone(), LDAP, definition);

            host = zone.getZone().getIdentityZone().getSubdomain() + ".localhost";
            IdentityZoneHolder.clear();

            listener = (ApplicationListener<AbstractUaaEvent>) mock(ApplicationListener.class);
            configurableApplicationContext.addApplicationListener(listener);

            testLogger = new InterceptingLogger();
            originalAuditServiceLogger = loggingAuditService.getLogger();
            loggingAuditService.setLogger(testLogger);
        } catch (Exception e) {
            Assumptions.assumeTrue(e == null,
                    () -> "Aborting: could not setup because of exception: " + e.getMessage());
        }
    }

    @AfterEach
    void tearDown() throws Exception {
        getMockMvc().perform(
                        delete("/identity-zones/{id}", zone.getZone().getIdentityZone().getId())
                                .header("Authorization", "Bearer " + zone.getDefaultZoneAdminToken())
                                .accept(APPLICATION_JSON)
                )
                .andExpect(status().isOk());
        MockMvcUtils.removeEventListener(webApplicationContext, listener);
    }

    @AfterEach
    void putBackOriginalLogger() {
        loggingAuditService.setLogger(originalAuditServiceLogger);
    }

    @Test
    @DirtiesContext
    void acceptInvitation_for_ldap_user_whose_username_is_not_email() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("delete from expiring_code_store");
        String email = "marissa2@test.com";
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM users WHERE email=?", email);
        LdapIdentityProviderDefinition definition = provider.getConfig();
        definition.setEmailDomain(Collections.singletonList("test.com"));
        updateLdapProvider();
        String redirectUri = "http://" + host;

        URL url = MockMvcUtils.inviteUser(
                getWebApplicationContext(),
                getMockMvc(),
                email,
                zone.getAdminToken(),
                zone.getZone().getIdentityZone().getSubdomain(),
                zone.getScimInviteClient().getClientId(),
                LDAP,
                redirectUri
        );

        String code = MockMvcUtils.extractInvitationCode(url.toString());
        String userInfoOrigin = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String userInfoId = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select id from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        assertThat(userInfoOrigin).isEqualTo(LDAP);

        ResultActions actions = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header(HOST, host)
        );
        MvcResult result = actions.andExpect(status().isOk())
                .andExpect(content().string(containsString("Link your account")))
                .andExpect(content().string(containsString("Email: " + email)))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andExpect(content().string(containsString("<input type=\"submit\" value=\"Sign in\" class=\"island-button\"/>")))
                .andReturn();

        code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        String expectRedirectToLogin = "/login?success=invite_accepted&form_redirect_uri=" + URLEncoder.encode(redirectUri, Charset.defaultCharset());
        MockHttpServletRequestBuilder post = post("/invitations/accept_enterprise.do")
                .param("enterprise_username", "marissa2")
                .param("enterprise_password", LDAP)
                .param("enterprise_email", "email")
                .param("code", code)
                .header(HOST, host)
                .with(cookieCsrf());
        if (session!=null) {
            post = post.session(session);
        }
        getMockMvc().perform(post)
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectRedirectToLogin))
                .andExpect(unauthenticated())
                .andReturn();

        MockHttpServletRequestBuilder get = get(expectRedirectToLogin)
                .with(cookieCsrf())
                .header(HOST, host);
        if (session!=null) {
            get = get.session(session);
        }
        getMockMvc().perform(
                        get
                )
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("form_redirect_uri")))
                .andExpect(content().string(containsString(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8))));
        post = post("/login.do")
                .with(cookieCsrf())
                .param("username", "marissa2")
                .param("password", LDAP)
                .header(HOST, host)
                .param("form_redirect_uri", redirectUri);
        if (session!=null) {
            post = post.session(session);
        }
        getMockMvc().perform(
                        post
                )
                .andExpect(authenticated())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(redirectUri));

        String newUserInfoId = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select id from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String newUserInfoOrigin = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        String newUserInfoUsername = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select username from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId());
        assertThat(newUserInfoOrigin).isEqualTo(LDAP);
        assertThat(newUserInfoUsername).isEqualTo("marissa2");
        //ensure that a new user wasn't created
        assertThat(newUserInfoId).isEqualTo(userInfoId);

        //email mismatch
        getWebApplicationContext().getBean(JdbcTemplate.class).update("delete from expiring_code_store");
        email = "different@test.com";
        url = MockMvcUtils.inviteUser(getWebApplicationContext(), getMockMvc(), email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), LDAP, REDIRECT_URI);
        code = MockMvcUtils.extractInvitationCode(url.toString());

        actions = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header(HOST, host)
        );
        result = actions.andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andReturn();

        code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);

        session = (MockHttpSession) result.getRequest().getSession(false);
        post = post("/invitations/accept_enterprise.do")
                .param("enterprise_username", "marissa2")
                .param("enterprise_password", LDAP)
                .param("enterprise_email", "email")
                .param("code", code)
                .header(HOST, host)
                .with(cookieCsrf());
        if (session!=null) {
            post = post.session(session);
        }
        getMockMvc().perform(
                        post
                )
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().string(containsString("The authenticated email does not match the invited email. Please log in using a different account.")))
                .andReturn();
        boolean userVerified = Boolean.parseBoolean(getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select verified from users where email=? and identity_zone_id=?", String.class, email, zone.getZone().getIdentityZone().getId()));
        assertThat(userVerified).isFalse();
    }

    @Test
    void external_groups_whitelist() throws Exception {
        assumeTrue("ldap-groups-map-to-scopes.xml, ldap-groups-as-scopes.xml".contains(ldapGroup));
        AuthenticationManager manager = getWebApplicationContext().getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa3", "ldap3");

        LdapIdentityProviderDefinition def = provider.getConfig();
        def.addWhiteListedGroup("admins");
        def.addWhiteListedGroup("thirdmarissa");
        provider.setConfig(def);
        updateLdapProvider();

        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        Authentication auth = manager.authenticate(token);
        assertThat(auth).isNotNull()
                .isInstanceOf(UaaAuthentication.class);
        UaaAuthentication uaaAuth = (UaaAuthentication) auth;
        Set<String> externalGroups = uaaAuth.getExternalGroups();
        assertThat(externalGroups)
                .hasSize(2)
                .containsExactlyInAnyOrder("admins", "thirdmarissa");

        //default whitelist
        def = provider.getConfig();
        def.setExternalGroupsWhitelist(emptyList());
        provider.setConfig(def);
        updateLdapProvider();
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        auth = manager.authenticate(token);
        assertThat(auth).isInstanceOf(UaaAuthentication.class);
        uaaAuth = (UaaAuthentication) auth;
        externalGroups = uaaAuth.getExternalGroups();
        assertThat(externalGroups).isEmpty();

        IdentityZoneHolder.clear();
    }

    @Test
    void customUserAttributes() throws Exception {
        assumeTrue("ldap-groups-map-to-scopes.xml, ldap-groups-as-scopes.xml".contains(ldapGroup));

        final String MANAGER = "uaaManager";
        final String managers = "managers";
        final String denverCo = "Denver,CO";
        final String costCenter = "costCenter";
        final String costCenters = costCenter + "s";
        final String johnTheSloth = "John the Sloth";
        final String kariTheAntEater = "Kari the Ant Eater";
        final String firstName = "first_name";
        final String familyName = "family_name";
        final String phoneNumber = "phone_number";
        final String emailVerified = "email_verified";

        Map<String, Object> attributeMappings = new HashMap<>();
        LdapIdentityProviderDefinition definition = provider.getConfig();

        attributeMappings.put("user.attribute." + managers, MANAGER);
        attributeMappings.put("user.attribute." + costCenters, costCenter);

        //test to remap the user/person properties
        attributeMappings.put(firstName, "sn");
        attributeMappings.put(phoneNumber, "givenname");
        attributeMappings.put(familyName, "telephonenumber");
        attributeMappings.put(emailVerified, "emailVerified");

        definition.setAttributeMappings(attributeMappings);
        provider.setConfig(definition);
        updateLdapProvider();

        String username = "marissa9";
        String password = "ldap9";
        MvcResult result = performUiAuthentication(username, password, HttpStatus.FOUND, true);

        UaaAuthentication authentication = (UaaAuthentication) ((SecurityContext) result.getRequest().getSession().getAttribute(SPRING_SECURITY_CONTEXT_KEY)).getAuthentication();

        assertThat(authentication.getUserAttributes()).as("Expected two user attributes").hasSize(2)
                .as("Expected cost center attribute").containsKey(costCenters)
                .as("Expected manager attribute").containsKey(managers);
        assertThat(authentication.getUserAttributes().getFirst(costCenters)).isEqualTo(denverCo);
        assertThat(authentication.getUserAttributes().get(managers)).as("Expected 2 manager attribute values").hasSize(2)
                .containsExactlyInAnyOrder(johnTheSloth, kariTheAntEater);

        assertThat(getFamilyName(username)).isEqualTo("8885550986");
        assertThat(getPhoneNumber(username)).isEqualTo("Marissa");
        assertThat(getGivenName(username)).isEqualTo("Marissa9");
        assertThat(getVerified(username)).isTrue();
    }

    @Test
    void loginInNonDefaultZone() throws Exception {
        assumeFalse(!(ldapProfile.contains("ldap-search-and-bind.xml") &&
                ldapGroup.contains("ldap-groups-map-to-scopes.xml")));

        getMockMvc().perform(get("/login").header(HOST, host))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .with(cookieCsrf())
                        .header(HOST, host)
                        .param("username", "marissa2")
                        .param("password", LDAP)
                )
                .andExpect(status().isFound())
                .andExpect(authenticated())
                .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        UaaUser user = getWebApplicationContext().getBean(UaaUserDatabase.class).retrieveUserByName("marissa2", LDAP);
        IdentityZoneHolder.clear();
        assertThat(user).isNotNull();
        assertThat(user.getOrigin()).isEqualTo(LDAP);
        assertThat(user.getZoneId()).isEqualTo(zone.getZone().getIdentityZone().getId());

        provider.setActive(false);
        MockMvcUtils.createIdpUsingWebRequest(getMockMvc(), zone.getZone().getIdentityZone().getId(), zone.getZone().getZoneAdminToken(), provider, status().isOk(), true);

        getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .with(cookieCsrf())
                        .header(HOST, host)
                        .param("username", "marissa2")
                        .param("password", LDAP))
                .andExpect(status().isFound())
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error=login_failure"));

        provider.setActive(true);
        MockMvcUtils.createIdpUsingWebRequest(getMockMvc(), zone.getZone().getIdentityZone().getId(), zone.getZone().getZoneAdminToken(), provider, status().isOk(), true);

        getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .with(cookieCsrf())
                        .header(HOST, host)
                        .param("username", "marissa2")
                        .param("password", LDAP))
                .andExpect(status().isFound())
                .andExpect(authenticated())
                .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        user = getWebApplicationContext().getBean(UaaUserDatabase.class).retrieveUserByName("marissa2", LDAP);
        IdentityZoneHolder.clear();
        assertThat(user).isNotNull();
        assertThat(user.getOrigin()).isEqualTo(LDAP);
        assertThat(user.getZoneId()).isEqualTo(zone.getZone().getIdentityZone().getId());
        assertThat(user.getEmail()).isEqualTo("marissa2@test.com");
    }

    @Test
    void loginPartialResultExceptionOnGroupSearch() throws Exception {
        getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .with(cookieCsrf())
                        .header(HOST, host)
                        .param("username", "marissa8")
                        .param("password", "ldap8"))
                .andExpect(status().isFound())
                .andExpect(authenticated())
                .andExpect(redirectedUrl("/"));

        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        UaaUser user = getWebApplicationContext().getBean(UaaUserDatabase.class).retrieveUserByName("marissa8", LDAP);
        IdentityZoneHolder.clear();
        assertThat(user).isNotNull();
        assertThat(user.getOrigin()).isEqualTo(LDAP);
        assertThat(user.getZoneId()).isEqualTo(zone.getZone().getIdentityZone().getId());
    }

    @Test
    void member_of_search() throws Exception {
        assumeTrue("ldap-groups-map-to-scopes.xml".contains(ldapGroup));
        transferDefaultMappingsToZone(zone.getZone().getIdentityZone());
        provider.getConfig().setGroupSearchBase("memberOf");
        updateLdapProvider();

        Object securityContext = getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .with(cookieCsrf())
                        .header(HOST, host)
                        .param("username", "marissa10")
                        .param("password", "ldap10"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andReturn().getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        assertThat(securityContext).isInstanceOf(SecurityContext.class);
        String[] list = new String[]{
                "internal.read",
                "internal.everything",
                "internal.superuser"
        };
        Authentication authentication = ((SecurityContext) securityContext).getAuthentication();
        validateUserAuthorities(list, authentication);
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        UaaUser user = getWebApplicationContext().getBean(UaaUserDatabase.class).retrieveUserByName("marissa10", LDAP);
        IdentityZoneHolder.clear();
        assertThat(user).isNotNull();
        assertThat(user.getOrigin()).isEqualTo(LDAP);
        assertThat(user.getZoneId()).isEqualTo(zone.getZone().getIdentityZone().getId());
    }

    ClassPathXmlApplicationContext getBeanContext() {
        DynamicZoneAwareAuthenticationManager zm = getWebApplicationContext().getBean(DynamicZoneAwareAuthenticationManager.class);
        zm.getLdapAuthenticationManager(zone.getZone().getIdentityZone(), provider).getLdapAuthenticationManager();
        return zm.getLdapAuthenticationManager(zone.getZone().getIdentityZone(), provider).getContext();
    }

    public Object getBean(String name) {
        ClassPathXmlApplicationContext beanContext = getBeanContext();
        return beanContext.getBean(name);
    }

    public <T> T getBean(Class<T> clazz) {
        return getBeanContext().getBean(clazz);
    }

    @Test
    void printProfileType() {
        assertThat(getBean("testLdapProfile")).isEqualTo(ldapProfile);
        assertThat(getBean("testLdapGroup")).isEqualTo(ldapGroup);
    }

    @Test
    void read_and_write_config_then_login() throws Exception {
        String response = getMockMvc().perform(
                        get("/identity-providers/" + provider.getId())
                                .header(ACCEPT, APPLICATION_JSON)
                                .header(HOST, host)
                                .header(AUTHORIZATION, "Bearer " + zone.getAdminToken())
                )
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(response).doesNotContain("bindPassword");
        provider = JsonUtils.readValue(response, new TypeReference<>() {
        });
        assertThat(provider.getConfig().getBindPassword()).isNull();

        getMockMvc().perform(
                        put("/identity-providers/" + provider.getId())
                                .content(JsonUtils.writeValueAsString(provider))
                                .header(CONTENT_TYPE, APPLICATION_JSON)
                                .header(ACCEPT, APPLICATION_JSON)
                                .header(HOST, host)
                                .header(AUTHORIZATION, "Bearer " + zone.getAdminToken())
                )
                .andExpect(status().isOk());

        testSuccessfulLogin();
    }

    @Test
    void login() throws Exception {
        getMockMvc().perform(
                        get("/login")
                                .header(HOST, host))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        getMockMvc().perform(
                        post("/login.do").accept(TEXT_HTML_VALUE)
                                .header(HOST, host)
                                .with(cookieCsrf())
                                .param("username", "marissa")
                                .param("password", "koaladsada"))
                .andExpect(status().isFound())
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error=login_failure"));

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(3)).onApplicationEvent(captor.capture());
        List<AbstractUaaEvent> allValues = captor.getAllValues();
        assertThat(allValues.get(2)).isInstanceOf(IdentityProviderAuthenticationFailureEvent.class);
        IdentityProviderAuthenticationFailureEvent event = (IdentityProviderAuthenticationFailureEvent) allValues.get(2);
        assertThat(event.getUsername()).isEqualTo("marissa");
        assertThat(event.getAuthenticationType()).isEqualTo(OriginKeys.LDAP);

        testLogger.reset();
        testSuccessfulLogin();

        assertThat(testLogger.getMessageCount()).isEqualTo(5);
        String zoneId = zone.getZone().getIdentityZone().getId();
        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(zoneId)
                .stream().filter(dbUser -> "marissa2".equals(dbUser.getUserName())).findFirst().get();
        String userCreatedLogMessage = testLogger.getFirstLogMessageOfType(AuditEventType.UserCreatedEvent);
        String expectedMessage = "UserCreatedEvent ('[\"user_id=%s\",\"username=marissa2\"]'): principal=%s, origin=[caller=null], identityZoneId=[%s]".formatted(
                createdUser.getId(), createdUser.getId(), zoneId
        );
        assertThat(userCreatedLogMessage).isEqualTo(expectedMessage);

        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(5)).onApplicationEvent(captor.capture());
        allValues = captor.getAllValues();
        assertThat(allValues.get(7)).isInstanceOf(IdentityProviderAuthenticationSuccessEvent.class);
        IdentityProviderAuthenticationSuccessEvent successEvent = (IdentityProviderAuthenticationSuccessEvent) allValues.get(7);
        assertThat(successEvent.getAuthenticationType()).isEqualTo(OriginKeys.LDAP);
    }

    // see also similar test for SAML in SamlAuthenticationMockMvcTests.java
    @Test
    void passcodeGrantIdTokenContainsExternalGroupsAsRolesClaim() throws Exception {
        assumeTrue("ldap-groups-as-scopes.xml".equals(ldapGroup) || "ldap-groups-map-to-scopes.xml".equals(ldapGroup));

        LdapIdentityProviderDefinition definition = provider.getConfig();
        // External groups will only appear as roles if they are whitelisted
        definition.setExternalGroupsWhitelist(Collections.singletonList("*"));
        // External groups are currently only stored in the db if StoreCustomAttributes is true
        definition.setStoreCustomAttributes(true);
        provider.setConfig(definition);
        updateLdapProvider();

        // This user, their password, and their group membership are all defined in ldap_init.ldif
        String username = "marissa";
        String password = "koala";
        String[] expectedGroups = new String[]{"marissagroup1", "marissagroup2"};

        // You need the openid scope in order to get an id_token,
        // and you need the roles scope in order to have the "roles" claim included into the id_token,
        // so we put both of these scopes on the client.
        String clientId = "roles_test_client";
        createClient(getWebApplicationContext(),
                new UaaClientDetails(clientId, null, "roles,openid", "password,refresh_token", null),
                zone.getZone().getIdentityZone()
        );

        // Log in to the UI to get a session cookie as the user
        MockHttpSession session = (MockHttpSession) getMockMvc().perform(
                        post("/login.do").accept(TEXT_HTML_VALUE)
                                .header(HOST, host)
                                .with(cookieCsrf())
                                .param("username", username)
                                .param("password", password)
                )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated())
                .andReturn().getRequest().getSession(false);

        // Using the user's session cookie, get a one-time passcode
        MockHttpServletRequestBuilder get = get("/passcode")
                .header(HOST, host)
                .accept(APPLICATION_JSON);
        if (session!=null) {
            get = get.session(session);
        }
        String content = mockMvc.perform(
                        get
                )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String passcode = JsonUtils.readValue(content, String.class);

        // Using the passcode, perform a password grant to get back tokens
        String response = mockMvc.perform(
                        post("/oauth/token")
                                .param("client_id", clientId)
                                .param("client_secret", "")
                                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                                .param("passcode", passcode)
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_FORM_URLENCODED)
                                .header(HOST, host)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });

        String accessToken = (String) tokens.get(ACCESS_TOKEN);
        Jwt accessTokenJwt = JwtHelper.decode(accessToken);
        Map<String, Object> accessTokenClaims = JsonUtils.readValue(accessTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        List<String> accessTokenScopes = (List<String>) accessTokenClaims.get("scope");
        // Check that the user had the roles scope, which is a pre-requisite for getting roles returned in the id_token
        assertThat(accessTokenScopes).contains("roles");

        Jwt idTokenJwt = JwtHelper.decode((String) tokens.get("id_token"));
        Map<String, Object> claims = JsonUtils.readValue(idTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        List<String> idTokenRoles = (List<String>) claims.get("roles");
        assertThat(idTokenRoles).containsExactlyInAnyOrder(expectedGroups);

        // As an aside, the /userinfo endpoint should also return the user's roles
        String userInfoContent = mockMvc.perform(
                        get("/userinfo")
                                .header(HOST, host)
                                .header("Authorization", "Bearer " + accessToken)
                                .accept(APPLICATION_JSON)
                )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> userInfo = JsonUtils.readValue(userInfoContent, new TypeReference<Map<String, Object>>() {
        });
        List<String> userInfoRoles = (List<String>) userInfo.get("roles");
        assertThat(userInfoRoles).containsExactlyInAnyOrder(expectedGroups);

        // We also got back a refresh token. When they use it, the refreshed id_token should also have the roles claim.
        String refreshToken = (String) tokens.get(REFRESH_TOKEN);
        String refreshTokenResponse = mockMvc.perform(
                        post("/oauth/token")
                                .param("client_id", clientId)
                                .param("client_secret", "")
                                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN)
                                .param("refresh_token", refreshToken)
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_FORM_URLENCODED)
                                .header(HOST, host)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> refreshedTokens = JsonUtils.readValue(refreshTokenResponse, new TypeReference<Map<String, Object>>() {
        });
        Jwt refreshedIdTokenJwt = JwtHelper.decode((String) refreshedTokens.get("id_token"));
        Map<String, Object> refreshedClaims = JsonUtils.readValue(refreshedIdTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        List<String> refreshedIdTokenRoles = (List<String>) refreshedClaims.get("roles");
        assertThat(refreshedIdTokenRoles).containsExactlyInAnyOrder(expectedGroups);
    }

    @Test
    void twoLdapServers() throws Exception {
        // Setup second ldap server
        InMemoryLdapServer secondLdapServer;
        String ldapBaseUrl;
        if (getLdapUrl().contains("ldap://")) {
            secondLdapServer = InMemoryLdapServer.startLdap();
        } else {
            secondLdapServer = InMemoryLdapServer.startLdapWithTls(KEYSTORE);
        }
        ldapBaseUrl = getLdapUrl() + " " + secondLdapServer.getUrl();

        provider.getConfig().setBaseUrl(ldapBaseUrl);
        updateLdapProvider();

        try {
            // Actually test it
            testSuccessfulLogin();
            stopLdapServer();

            testSuccessfulLogin();
            stopLdapServer(secondLdapServer);

        } finally {
            stopLdapServer();
            stopLdapServer(secondLdapServer);
            Thread.sleep(1500);
        }
    }

    private void stopLdapServer(InMemoryLdapServer ldapServer) {
        if (ldapServer.isRunning()) {
            ldapServer.stop();
        }
    }

    @Test
    void username_with_space() throws Exception {
        getMockMvc().perform(
                        post("/login.do").accept(TEXT_HTML_VALUE)
                                .header(HOST, host)
                                .with(cookieCsrf())
                                .param("username", "marissa 11")
                                .param("password", "ldap11"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    void testSuccessfulLogin() throws Exception {
        getMockMvc().perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .header(HOST, host)
                        .with(cookieCsrf())

                        .param("username", "marissa2")
                        .param("password", LDAP))
                .andExpect(status().isFound())
                .andExpect(authenticated())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void authenticateWithUTF8Characters() throws Exception {
        String username = "\u7433\u8D3A";

        HttpSession session =
                getMockMvc().perform(
                                post("/login.do").accept(TEXT_HTML_VALUE)
                                        .header(HOST, host)
                                        .with(cookieCsrf())
                                        .param("username", username)
                                        .param("password", "koala"))
                        .andExpect(status().isFound())
                        .andExpect(redirectedUrl("/"))
                        .andExpect(authenticated())
                        .andReturn().getRequest().getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(SPRING_SECURITY_CONTEXT_KEY)).isNotNull();
        Authentication authentication = ((SecurityContext) session.getAttribute(SPRING_SECURITY_CONTEXT_KEY)).getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test
    void authenticate() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa3@test.com\"");
    }

    @Test
    void extendedAttributes() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa3@test.com\"");
        assertThat(getGivenName(username)).isEqualTo("Marissa");
        assertThat(getFamilyName(username)).isEqualTo("Lastnamerton");
        assertThat(getPhoneNumber(username)).isEqualTo("8885550986");
        assertThat(getVerified(username)).isFalse();
    }

    @Test
    void authenticateInactiveIdp() throws Exception {
        provider.setActive(false);
        updateLdapProvider();
        String username = "marissa3";
        String password = "ldap3";
        performAuthentication(username, password, HttpStatus.UNAUTHORIZED);
    }

    @Test
    void authenticateFailure() throws Exception {
        String username = "marissa3";
        String password = "ldapsadadasas";
        MockHttpServletRequestBuilder post =
                post("/authenticate")
                        .header(HOST, host)
                        .accept(MediaType.APPLICATION_JSON)
                        .param("username", username)
                        .param("password", password);
        getMockMvc().perform(post)
                .andExpect(status().isUnauthorized());

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(3)).onApplicationEvent(captor.capture());
        List<AbstractUaaEvent> allValues = captor.getAllValues();
        assertThat(allValues.get(2)).isInstanceOf(IdentityProviderAuthenticationFailureEvent.class);
        IdentityProviderAuthenticationFailureEvent event = (IdentityProviderAuthenticationFailureEvent) allValues.get(2);
        assertThat(event.getUsername()).isEqualTo("marissa3");
        assertThat(event.getAuthenticationType()).isEqualTo(OriginKeys.LDAP);
    }

    @Test
    void validateOriginForNonLdapUser() throws Exception {
        String username = "marissa";
        String password = "koala";
        ScimUser user = new ScimUser(null, username, "Marissa", "Koala");
        user.setPrimaryEmail("marissa@test.org");
        user.setPassword(password);
        MockMvcUtils.createUserInZone(getMockMvc(), zone.getAdminToken(), user, zone.getZone().getIdentityZone().getSubdomain());

        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa@test.org\"");
        assertThat(getOrigin(username)).isEqualTo(OriginKeys.UAA);
    }

    @Test
    void validateOriginAndEmailForLdapUser() throws Exception {
        String username = "marissa3";
        String password = "ldap3";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa3@test.com\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("marissa3@test.com");
    }

    @Test
    void validateEmailMissingForLdapUser() throws Exception {
        String username = "marissa7";
        String password = "ldap7";
        MvcResult result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa7@user.from.ldap.cf\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("marissa7@user.from.ldap.cf");
    }

    @Test
    void validateCustomEmailForLdapUser() throws Exception {
        provider.getConfig().setMailSubstitute("{0}@ldaptest.org");
        updateLdapProvider();
        String username = "marissa7";
        String password = "ldap7";
        MvcResult result = performAuthentication(username, password);

        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa7@ldaptest.org\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("marissa7@ldaptest.org");
        provider.getConfig().setMailSubstitute(null);
        updateLdapProvider();

        //null value should go back to default email
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa3@test.com\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("marissa3@test.com");

        username = "marissa7";
        password = "ldap7";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa7@user.from.ldap.cf\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("marissa7@user.from.ldap.cf");

        //non null value
        provider.getConfig().setMailSubstitute("user-{0}@testldap.org");
        updateLdapProvider();
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"user-marissa7@testldap.org\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("user-marissa7@testldap.org");

        //value not overridden
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"marissa3@test.com\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("marissa3@test.com");

        provider.getConfig().setMailSubstituteOverridesLdap(true);
        updateLdapProvider();
        username = "marissa3";
        password = "ldap3";
        result = performAuthentication(username, password);
        assertThat(result.getResponse().getContentAsString()).contains("\"username\":\"" + username + "\"")
                .contains("\"email\":\"user-marissa3@testldap.org\"");
        assertThat(getOrigin(username)).isEqualTo(LDAP);
        assertThat(getEmail(username)).isEqualTo("user-marissa3@testldap.org");
    }

    private String getOrigin(String username) {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=? and identity_zone_id=?", String.class, username, zone.getZone().getIdentityZone().getId());
    }

    private String getEmail(String username) {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select email from users where username=? and origin=? and identity_zone_id=?", String.class, username, LDAP, zone.getZone().getIdentityZone().getId());
    }

    private String getGivenName(String username) {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select givenname from users where username=? and origin=? and identity_zone_id=?", String.class, username, LDAP, zone.getZone().getIdentityZone().getId());
    }

    private String getFamilyName(String username) {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select familyname from users where username=? and origin=? and identity_zone_id=?", String.class, username, LDAP, zone.getZone().getIdentityZone().getId());
    }

    private String getPhoneNumber(String username) {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select phonenumber from users where username=? and origin=? and identity_zone_id=?", String.class, username, LDAP, zone.getZone().getIdentityZone().getId());
    }

    private boolean getVerified(String username) {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select verified from users where username=? and origin=? and identity_zone_id=?", Boolean.class, username, LDAP, zone.getZone().getIdentityZone().getId());
    }

    private MvcResult performAuthentication(String username, String password) throws Exception {
        return performAuthentication(username, password, HttpStatus.OK);
    }

    private MvcResult performAuthentication(String username, String password, HttpStatus status) throws Exception {
        MockHttpServletRequestBuilder post =
                post("/authenticate")
                        .header(HOST, host)
                        .accept(MediaType.APPLICATION_JSON)
                        .param("username", username)
                        .param("password", password);

        return getMockMvc().perform(post)
                .andExpect(status().is(status.value()))
                .andReturn();
    }

    private MvcResult performUiAuthentication(String username, String password, HttpStatus status, boolean authenticated) throws Exception {
        MockHttpServletRequestBuilder post =
                post("/login.do")
                        .with(cookieCsrf())
                        .header(HOST, host)
                        .accept(MediaType.TEXT_HTML)
                        .param("username", username)
                        .param("password", password);

        return getMockMvc().perform(post)
                .andExpect(status().is(status.value()))
                .andExpect(authenticated ? authenticated() : unauthenticated())
                .andReturn();
    }

    int getRandomPortOffset() {
        return ThreadLocalRandom.current().nextInt(10000);
    }

    @Test
    void ldapScopes() {
        assumeTrue("ldap-groups-as-scopes.xml".equals(ldapGroup));
        AuthenticationManager manager = (AuthenticationManager) getBean("ldapAuthenticationManager");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa3", "ldap3");
        Authentication auth = manager.authenticate(token);
        assertThat(auth).isNotNull();
        String[] list = new String[]{
                "uaa.admin",
                "cloud_controller.read",
                "thirdmarissa"
        };
        assertThat(list).containsExactlyInAnyOrder(getAuthorities(auth.getAuthorities()));
    }

    @Test
    void ldapScopesFromChainedAuth() {
        assumeTrue("ldap-groups-as-scopes.xml".equals(ldapGroup));
        AuthenticationManager manager = (AuthenticationManager) getWebApplicationContext().getBean("zoneAwareAuthzAuthenticationManager");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa3", "ldap3");
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        Authentication auth = manager.authenticate(token);
        assertThat(auth).isNotNull();
        List<String> list = new LinkedList<>(UserConfig.DEFAULT_ZONE_GROUPS);
        list.add("uaa.admin");
        list.add("thirdmarissa");
        list.add("cloud_controller.read");
        assertThat(list).containsExactlyInAnyOrder(getAuthorities(auth.getAuthorities()));
        IdentityZoneHolder.clear();
    }

    @Test
    void nestedLdapScopes() {
        if (!"ldap-groups-as-scopes.xml".equals(ldapGroup)) {
            return;
        }
        Set<String> defaultAuthorities = Sets.newHashSet(zone.getZone().getIdentityZone().getConfig().getUserConfig().getDefaultGroups());
        AuthenticationManager manager = getWebApplicationContext().getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa4", "ldap4");
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        Authentication auth = manager.authenticate(token);
        assertThat(auth).isNotNull();
        defaultAuthorities.addAll(Arrays.asList("test.read", "test.write", "test.everything"));
        assertThat(UaaStringUtils.getStringsFromAuthorities(auth.getAuthorities())).containsExactlyInAnyOrderElementsOf(defaultAuthorities);
        IdentityZoneHolder.clear();
    }

    void transferDefaultMappingsToZone(IdentityZone zone) {
        JdbcScimGroupExternalMembershipManager exm = getWebApplicationContext().getBean(JdbcScimGroupExternalMembershipManager.class);
        List<ScimGroupExternalMember> defaultExternalMembers = exm.getExternalGroupMappings(IdentityZone.getUaaZoneId());
        List<String> defaultMappings = defaultExternalMembers.stream().map(m -> (m.getDisplayName()+"|"+m.getExternalGroup())).toList();
        ScimGroupProvisioning gp = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        IdentityZoneHolder.set(zone);
        for (String s : defaultMappings) {
            String[] groupData = StringUtils.split(s, "|");
            String internalName = groupData[0];
            String externalName = groupData[1];
            ScimGroup group = new ScimGroup(internalName);
            group.setZoneId(zone.getId());
            try {
                group = gp.create(group, IdentityZoneHolder.get().getId());
            } catch (ScimResourceAlreadyExistsException e) {
                String filter = "displayName eq \"" + internalName + "\"";
                group = gp.query(filter, IdentityZoneHolder.get().getId()).getFirst();
            }
            exm.mapExternalGroup(group.getId(), externalName, OriginKeys.LDAP, zone.getId());
        }
    }

    void doTestNestedLdapGroupsMappedToScopes(String username, String password, String[] expected) {
        assumeTrue("ldap-groups-map-to-scopes.xml".equals(ldapGroup));
        transferDefaultMappingsToZone(zone.getZone().getIdentityZone());
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        AuthenticationManager manager = getWebApplicationContext().getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        Authentication auth = manager.authenticate(token);
        assertThat(auth).isNotNull();
        validateUserAuthorities(expected, auth);
        IdentityZoneHolder.clear();
    }

    void validateUserAuthorities(String[] expected, Authentication auth) {
        Set<String> defaultAuthorities = new HashSet<>(zone.getZone().getIdentityZone().getConfig().getUserConfig().getDefaultGroups());
        Collections.addAll(defaultAuthorities, expected);
        assertThat(UaaStringUtils.getStringsFromAuthorities(auth.getAuthorities())).containsExactlyInAnyOrderElementsOf(defaultAuthorities);
    }

    @Test
    void nestedLdapGroupsMappedToScopes() {
        String[] list = new String[]{
                "internal.read",
                "internal.write",
                "internal.everything",
                "internal.superuser"
        };
        doTestNestedLdapGroupsMappedToScopes("marissa4", "ldap4", list);
    }

    @Test
    void nestedLdapGroupsMappedToScopes2() {
        String[] list = new String[]{
                "internal.read",
                "internal.write",
        };
        doTestNestedLdapGroupsMappedToScopes("marissa5", "ldap5", list);
    }

    @Test
    void nestedLdapGroupsMappedToScopes3() {
        String[] list = new String[]{
                "internal.read",
        };
        doTestNestedLdapGroupsMappedToScopes("marissa6", "ldap6", list);
    }

    @Test
    void nestedLdapGroupsMappedToScopesWithDefaultScopes() {
        String username = "marissa4";
        String password = "ldap4";
        String[] list = new String[]{
                "internal.read",
                "internal.write",
                "internal.everything",
                "internal.superuser"
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username, password, list);
    }

    @Test
    void nestedLdapGroupsMappedToScopesWithDefaultScopes2() {

        String username = "marissa5";
        String password = "ldap5";
        String[] list = new String[]{
                "internal.read",
                "internal.write",
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username, password, list);
    }

    @Test
    void nestedLdapGroupsMappedToScopesWithDefaultScopes3() {
        String username = "marissa6";
        String password = "ldap6";
        String[] list = new String[]{
                "internal.read",
        };
        doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(username, password, list);
    }

    @Test
    void stopIfException() throws Exception {
        if ("ldap-simple-bind.xml".equals(ldapProfile) && "ldap-groups-null.xml".equals(ldapGroup)) {
            ScimUser user = new ScimUser();
            String userName = "user" + new RandomValueStringGenerator().generate() + "@example.com";
            user.setUserName(userName);
            user.addEmail(userName);
            user.setVerified(true);
            user.setPassword("n1cel0ngp455w0rd");
            user = MockMvcUtils.createUserInZone(getMockMvc(), zone.getAdminToken(), user, zone.getZone().getIdentityZone().getSubdomain());
            assertThat(user.getId()).isNotNull();
            performAuthentication(userName, "n1cel0ngp455w0rd", HttpStatus.OK);
        }
    }

    void doTestNestedLdapGroupsMappedToScopesWithDefaultScopes(String username, String password, String[] expected) {
        assumeTrue("ldap-groups-map-to-scopes.xml".equals(ldapGroup));
        AuthenticationManager manager = getWebApplicationContext().getBean(DynamicZoneAwareAuthenticationManager.class);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        transferDefaultMappingsToZone(zone.getZone().getIdentityZone());
        IdentityZoneHolder.set(zone.getZone().getIdentityZone());
        Authentication auth = manager.authenticate(token);
        assertThat(auth).isNotNull();
        Set<String> defaultAuthorities = Sets.newHashSet(zone.getZone().getIdentityZone().getConfig().getUserConfig().getDefaultGroups());
        defaultAuthorities.addAll(Arrays.asList(expected));
        assertThat(UaaStringUtils.getStringsFromAuthorities(auth.getAuthorities())).containsExactlyInAnyOrderElementsOf(defaultAuthorities);
    }

    String[] getAuthorities(Collection<? extends GrantedAuthority> authorities) {
        String[] result = new String[authorities != null ? authorities.size() : 0];
        if (result.length > 0) {
            int index = 0;
            for (GrantedAuthority a : authorities) {
                result[index++] = a.getAuthority();
            }
        }
        return result;
    }

    void updateLdapProvider() throws Exception {
        provider = MockMvcUtils.createIdpUsingWebRequest(
                getMockMvc(),
                zone.getZone().getIdentityZone().getId(),
                zone.getZone().getZoneAdminToken(),
                provider,
                status().isOk(),
                true
        );
    }
}
