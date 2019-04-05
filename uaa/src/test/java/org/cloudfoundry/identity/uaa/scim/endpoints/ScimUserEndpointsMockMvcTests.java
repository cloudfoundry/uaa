package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.Lists;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.invitations.InvitationConstants;
import org.cloudfoundry.identity.uaa.mfa.*;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.UserAlreadyVerifiedException;
import org.cloudfoundry.identity.uaa.scim.test.JsonObjectMatcherUtils;
import org.cloudfoundry.identity.uaa.test.*;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.*;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.util.StringUtils.hasText;

@ExtendWith(ZoneSeederExtension.class)
@DefaultTestContext
class ScimUserEndpointsMockMvcTests {
    private static final String HTTP_REDIRECT_EXAMPLE_COM = "http://redirect.example.com";
    private static final String USER_PASSWORD = "pas5Word";
    private String scimReadWriteToken;
    private String scimCreateToken;
    private String uaaAdminToken;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private ClientDetails clientDetails;
    private ScimUserProvisioning usersRepository;
    private JdbcIdentityProviderProvisioning identityProviderProvisioning;
    private ExpiringCodeStore codeStore;
    private JdbcUserGoogleMfaCredentialsProvisioning mfaCredentialsProvisioning;
    private MfaProviderProvisioning mfaProviderProvisioning;
    private int usersMaxCount;

    @Autowired
    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;

    @Autowired
    private JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    @Autowired
    private JdbcMfaProviderProvisioning jdbcMfaProviderProvisioning;

    @BeforeEach
    void setUp() throws Exception {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin");
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,uaa.admin";
        clientDetails = MockMvcUtils.createClient(mockMvc, adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("openid", "foo", "bar"), Arrays.asList("client_credentials", "password"), authorities);
        scimReadWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "scim.read scim.write password.write");
        scimCreateToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "scim.create");
        usersRepository = webApplicationContext.getBean(ScimUserProvisioning.class);
        identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        codeStore = webApplicationContext.getBean(ExpiringCodeStore.class);
        mfaCredentialsProvisioning = webApplicationContext.getBean(JdbcUserGoogleMfaCredentialsProvisioning.class);
        mfaProviderProvisioning = webApplicationContext.getBean(JdbcMfaProviderProvisioning.class);
        uaaAdminToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "uaa.admin");

        usersMaxCount = Integer.parseInt(webApplicationContext.getEnvironment().getProperty("userMaxCount"));
    }

    @AfterEach
    void tearDown() {
        jdbcIdentityZoneProvisioning.retrieveAll().forEach(identityZone -> jdbcMfaProviderProvisioning.deleteByIdentityZone(identityZone.getId()));
    }

    @Test
    void unauthorized_put_returns_401() throws Exception {
        mockMvc.perform(
                put("/Users/some-user")
        )
                .andExpect(status().isUnauthorized());

        mockMvc.perform(
                put("/Users")
        )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testCanCreateUserWithExclamationMark() throws Exception {
        String email = "joe!!@" + generator.generate().toLowerCase() + ".com";
        ScimUser user = getScimUser();
        user.getEmails().clear();
        user.setUserName(email);
        user.setPrimaryEmail(email);
        createUser(user, scimReadWriteToken, null);
    }

    @Test
    void test_Create_User_Too_Long_Password() throws Exception {
        String email = "joe@" + generator.generate().toLowerCase() + ".com";
        ScimUser user = getScimUser();
        user.setUserName(email);
        user.setPassword(new RandomValueStringGenerator(300).generate());
        ResultActions result = createUserAndReturnResult(user, scimReadWriteToken, null, null);
        result.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_password"))
                .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."))
                .andExpect(jsonPath("$.error_description").value("Password must be no more than 255 characters in length."));
    }

    @Test
    void test_Create_User_More_Than_One_Email() throws Exception {
        ScimUser scimUser = getScimUser();
        String secondEmail = "joe@" + generator.generate().toLowerCase() + ".com";
        scimUser.addEmail(secondEmail);
        createUserAndReturnResult(scimUser, scimReadWriteToken, null, null)
                .andExpect(status().isBadRequest());
    }

    @Test
    void testCreateUser() throws Exception {
        createUser(scimReadWriteToken);
    }

    @Test
    void testCreateUserWithScimCreateToken() throws Exception {
        createUser(scimCreateToken);
    }

    @Test
    void createUserWithUaaAdminToken() throws Exception {
        createUser(uaaAdminToken);
    }

    @Test
    void createUserInOtherZoneWithUaaAdminToken() throws Exception {
        IdentityZone otherIdentityZone = getIdentityZone();

        createUser(getScimUser(), uaaAdminToken, IdentityZone.getUaa().getSubdomain(), otherIdentityZone.getId());
    }

    @Test
    void default_password_policy_does_not_allow_empty_passwords() throws Exception {
        IdentityZone otherIdentityZone = getIdentityZone();
        ScimUser scimUser = getScimUser();
        scimUser.setPassword("");

        IdentityProvider<UaaIdentityProviderDefinition> uaa =
                webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).retrieveByOrigin(
                        OriginKeys.UAA,
                        otherIdentityZone.getId()
                );

        ResultActions result = createUserAndReturnResult(scimUser, uaaAdminToken, IdentityZone.getUaa().getSubdomain(), otherIdentityZone.getId());
        result.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Password must be at least 1 characters in length."));
    }

    @Test
    void createUserInOtherZoneWithUaaAdminTokenFromNonDefaultZone() throws Exception {
        IdentityZone identityZone = getIdentityZone();

        String authorities = "uaa.admin";
        clientDetails = MockMvcUtils.createClient(mockMvc, uaaAdminToken, "testClientId", "testClientSecret", null, null, Collections.singletonList("client_credentials"), authorities, null, identityZone);
        String uaaAdminTokenFromOtherZone = testClient.getClientCredentialsOAuthAccessToken("testClientId", "testClientSecret", "uaa.admin", identityZone.getSubdomain());

        byte[] requestBody = JsonUtils.writeValueAsBytes(getScimUser());
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + uaaAdminTokenFromOtherZone)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        post.with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"));
        post.header(HEADER, IdentityZone.getUaaZoneId());

        mockMvc.perform(post).andExpect(status().isForbidden());
    }

    @Test
    void verification_link() throws Exception {
        ScimUser joel = setUpScimUser();

        MockHttpServletRequestBuilder get = setUpVerificationLinkRequest(joel, scimCreateToken);

        MvcResult result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        VerificationResponse verificationResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), VerificationResponse.class);
        assertThat(verificationResponse.getVerifyLink().toString(), startsWith("http://localhost/verify_user"));

        String query = verificationResponse.getVerifyLink().getQuery();

        String code = getQueryStringParam(query, "code");
        assertThat(code, is(notNullValue()));

        ExpiringCode expiringCode = codeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
        assertThat(expiringCode.getIntent(), is(REGISTRATION.name()));
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
        });
        assertThat(data.get(InvitationConstants.USER_ID), is(notNullValue()));
        assertThat(data.get(CLIENT_ID), is(clientDetails.getClientId()));
        assertThat(data.get(REDIRECT_URI), is(HTTP_REDIRECT_EXAMPLE_COM));
    }

    @Test
    void verification_link_in_non_default_zone() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        MockMvcUtils.IdentityZoneCreationResult zoneResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String zonedClientId = "zonedClientId";
        String zonedClientSecret = "zonedClientSecret";
        BaseClientDetails zonedClientDetails = (BaseClientDetails) MockMvcUtils.createClient(mockMvc, zoneResult.getZoneAdminToken(), zonedClientId, zonedClientSecret, Collections.singleton("oauth"), null, Arrays.asList(new String[]{"client_credentials"}), "scim.create", null, zoneResult.getIdentityZone());
        zonedClientDetails.setClientSecret(zonedClientSecret);
        String zonedScimCreateToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, zonedClientDetails.getClientId(), zonedClientDetails.getClientSecret(), "scim.create", subdomain);

        ScimUser joel = setUpScimUser(zoneResult.getIdentityZone());

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify-link")
                .header("Host", subdomain + ".localhost")
                .header("Authorization", "Bearer " + zonedScimCreateToken)
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();
        VerificationResponse verificationResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), VerificationResponse.class);
        assertThat(verificationResponse.getVerifyLink().toString(), startsWith("http://" + subdomain + ".localhost/verify_user"));

        String query = verificationResponse.getVerifyLink().getQuery();

        String code = getQueryStringParam(query, "code");
        assertThat(code, is(notNullValue()));

        IdentityZoneHolder.set(zoneResult.getIdentityZone());
        ExpiringCode expiringCode = codeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        IdentityZoneHolder.clear();
        assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
        assertThat(expiringCode.getIntent(), is(REGISTRATION.name()));
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
        });
        assertThat(data.get(InvitationConstants.USER_ID), is(notNullValue()));
        assertThat(data.get(CLIENT_ID), is(zonedClientDetails.getClientId()));
        assertThat(data.get(REDIRECT_URI), is(HTTP_REDIRECT_EXAMPLE_COM));
    }

    @Test
    void verification_link_in_non_default_zone_using_switch() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        MockMvcUtils.IdentityZoneCreationResult zoneResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String zonedClientId = "admin";
        String zonedClientSecret = "adminsecret";
        String zonedScimCreateToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, zonedClientId, zonedClientSecret, "uaa.admin", null);

        ScimUser joel = setUpScimUser(zoneResult.getIdentityZone());

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify-link")
                .header("Host", "localhost")
                .header("Authorization", "Bearer " + zonedScimCreateToken)
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, subdomain)
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();
        VerificationResponse verificationResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), VerificationResponse.class);
        assertThat(verificationResponse.getVerifyLink().toString(), startsWith("http://" + subdomain + ".localhost/verify_user"));

        String query = verificationResponse.getVerifyLink().getQuery();

        String code = getQueryStringParam(query, "code");
        assertThat(code, is(notNullValue()));

        IdentityZoneHolder.set(zoneResult.getIdentityZone());
        ExpiringCode expiringCode = codeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        IdentityZoneHolder.clear();
        assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
        assertThat(expiringCode.getIntent(), is(REGISTRATION.name()));
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
        });
        assertThat(data.get(InvitationConstants.USER_ID), is(notNullValue()));
        assertThat(data.get(CLIENT_ID), is("admin"));
        assertThat(data.get(REDIRECT_URI), is(HTTP_REDIRECT_EXAMPLE_COM));
    }

    @Test
    void create_user_without_username() throws Exception {
        ScimUser user = new ScimUser(null, null, "Joel", "D'sa");
        user.setPassword("password");
        user.setPrimaryEmail("test@test.org");

        mockMvc.perform(post("/Users")
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)))
                .andExpect(status().isBadRequest())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", "A username must be provided.")
                                        .put("message", "A username must be provided.")
                                        .put("error", "invalid_scim_resource"))));
    }

    @Test
    void create_user_without_email() throws Exception {
        ScimUser user = new ScimUser(null, "a_user", "Joel", "D'sa");
        user.setPassword("password");

        mockMvc.perform(post("/Users")
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)))
                .andExpect(status().isBadRequest())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", "Exactly one email must be provided.")
                                        .put("message", "Exactly one email must be provided.")
                                        .put("error", "invalid_scim_resource"))));
    }

    @Test
    void create_user_then_update_without_email() throws Exception {
        ScimUser user = setUpScimUser();
        user.setEmails(null);

        mockMvc.perform(put("/Users/" + user.getId())
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)))
                .andExpect(status().isBadRequest())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", "Exactly one email must be provided.")
                                        .put("message", "Exactly one email must be provided.")
                                        .put("error", "invalid_scim_resource"))));
    }

    @Test
    void patch_user_to_inactive_then_login() throws Exception {
        ScimUser user = setUpScimUser();
        user.setVerified(true);
        boolean active = true;
        user.setActive(active);
        mockMvc.perform(
                patch("/Users/" + user.getId())
                        .header("Authorization", "Bearer " + scimReadWriteToken)
                        .header("If-Match", "\"" + user.getVersion() + "\"")
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active", equalTo(active)));

        performAuthentication(user, true);

        active = false;
        user.setActive(active);
        mockMvc.perform(
                patch("/Users/" + user.getId())
                        .header("Authorization", "Bearer " + scimReadWriteToken)
                        .header("If-Match", "\"" + (user.getVersion() + 1) + "\"")
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active", equalTo(active)));

        performAuthentication(user, false);

    }

    @Test
    void verification_link_unverified_error() throws Exception {
        ScimUser user = setUpScimUser();
        user.setVerified(true);
        usersRepository.update(user.getId(), user, IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder get = setUpVerificationLinkRequest(user, scimCreateToken);

        mockMvc.perform(get)
                .andExpect(status().isMethodNotAllowed())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", UserAlreadyVerifiedException.DESC)
                                        .put("message", UserAlreadyVerifiedException.DESC)
                                        .put("error", "user_already_verified"))));
    }

    @Test
    void verification_link_is_authorized_endpoint() throws Exception {
        ScimUser joel = setUpScimUser();

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify-link")
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isUnauthorized());
    }

    @Test
    void verification_link_secured_with_scimcreate() throws Exception {
        ScimUser joel = setUpScimUser();

        MockHttpServletRequestBuilder get = setUpVerificationLinkRequest(joel, scimReadWriteToken);

        mockMvc.perform(get)
                .andExpect(status().isForbidden());
    }

    @Test
    void verification_link_user_not_found() throws Exception {
        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/12345/verify-link")
                .header("Authorization", "Bearer " + scimCreateToken)
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", "User 12345 does not exist")
                                        .put("message", "User 12345 does not exist")
                                        .put("error", "scim_resource_not_found"))));
    }

    @Test
    void listUsers_in_anotherZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String zoneAdminToken = result.getZoneAdminToken();

        int usersMaxCountWithOffset = usersMaxCount + 1;
        for (int i = 0; i < usersMaxCountWithOffset; i++) {
            createUser(getScimUser(), zoneAdminToken, IdentityZone.getUaa().getSubdomain(), result.getIdentityZone().getId());
        }

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users").param("count", Integer.toString(usersMaxCountWithOffset))
                .header("X-Identity-Zone-Subdomain", subdomain)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .accept(APPLICATION_JSON);

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();
        SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        assertThat(searchResults.getResources().size(), is(usersMaxCount));
        assertThat(searchResults.getItemsPerPage(), is(usersMaxCount));
        assertThat(searchResults.getTotalResults(), is(usersMaxCountWithOffset));
    }

    @Test
    void testVerifyUser() throws Exception {
        verifyUser(scimReadWriteToken);
    }

    @Test
    void testVerifyUserWithScimCreateToken() throws Exception {
        verifyUser(scimCreateToken);
    }

    @Test
    void testCreateUserInZoneUsingAdminClient() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write", subdomain);

        createUser(zoneAdminToken, subdomain);
    }

    @Test
    void testCreateUserInZoneUsingZoneAdminUser() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String zoneAdminToken = result.getZoneAdminToken();
        createUser(getScimUser(), zoneAdminToken, IdentityZone.getUaa().getSubdomain(), result.getIdentityZone().getId());
    }

    @Test
    void testUserSelfAccess_Get_and_Post() throws Exception {
        ScimUser user = getScimUser();
        user.setPassword("secret");

        ScimUser savedUser = createUser(user, scimReadWriteToken, IdentityZone.getUaa().getSubdomain());

        String selfToken = testClient.getUserOAuthAccessToken("cf", "", savedUser.getUserName(), "secret", "");

        savedUser.setName(new ScimUser.Name("Given1", "Family1"));

        ScimUser updatedUser = updateUser(selfToken, HttpStatus.OK.value(), savedUser);

        getAndReturnUser(HttpStatus.OK.value(), updatedUser, selfToken);
    }

    @Test
    void testCreateUserInOtherZoneIsUnauthorized() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        String otherSubdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(otherSubdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write", subdomain);

        ScimUser user = getScimUser();

        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .with(new SetServerNameRequestPostProcessor(otherSubdomain + ".localhost"))
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post).andExpect(status().isUnauthorized());
    }

    @Test
    void testUnlockAccount() throws Exception {
        ScimUser userToLockout = createUser(uaaAdminToken);
        attemptUnsuccessfulLogin(5, userToLockout.getUserName(), "");

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setLocked(false);
        updateAccountStatus(userToLockout, alteredAccountStatus)
                .andExpect(status().isOk())
                .andExpect(content().json(JsonUtils.writeValueAsString(alteredAccountStatus)));

        attemptLogin(userToLockout)
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void testAccountStatusEmptyPatchDoesNotUnlock() throws Exception {
        ScimUser userToLockout = createUser(uaaAdminToken);
        attemptUnsuccessfulLogin(5, userToLockout.getUserName(), "");

        updateAccountStatus(userToLockout, new UserAccountStatus())
                .andExpect(status().isOk())
                .andExpect(content().json("{}"));

        attemptLogin(userToLockout)
                .andExpect(redirectedUrl("/login?error=account_locked"));
    }

    @Test
    void testUpdateStatusCannotLock() throws Exception {
        ScimUser user = createUser(uaaAdminToken);

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setLocked(true);
        updateAccountStatus(user, alteredAccountStatus)
                .andExpect(status().isBadRequest());

        attemptLogin(user)
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void testUnlockAccountWhenNotLocked() throws Exception {
        ScimUser userToLockout = createUser(uaaAdminToken);

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setLocked(false);
        updateAccountStatus(userToLockout, alteredAccountStatus)
                .andExpect(status().isOk())
                .andExpect(content().json(JsonUtils.writeValueAsString(alteredAccountStatus)));

        attemptLogin(userToLockout)
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void testForcePasswordExpireAccountInvalid() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(false);

        updateAccountStatus(user, alteredAccountStatus)
                .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void testForcePasswordExpireAccountExternalUser() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        user.setOrigin("NOT_UAA");
        updateUser(uaaAdminToken, HttpStatus.OK.value(), user);
        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(true);

        updateAccountStatus(user, alteredAccountStatus)
                .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void testForcePasswordChange() throws Exception {
        ScimUser user = createUser(uaaAdminToken);

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId(), IdentityZoneHolder.get().getId()));

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(true);

        updateAccountStatus(user, alteredAccountStatus)
                .andExpect(status().isOk())
                .andExpect(content().json(JsonUtils.writeValueAsString(alteredAccountStatus)));

        assertTrue(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void testTryMultipleStatusUpdatesWithInvalidLock() throws Exception {
        ScimUser user = createUser(uaaAdminToken);

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(true);
        alteredAccountStatus.setLocked(true);

        updateAccountStatus(user, alteredAccountStatus)
                .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId(), IdentityZoneHolder.get().getId()));

        attemptLogin(user)
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void testTryMultipleStatusUpdatesWithInvalidRemovalOfPasswordChange() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        attemptUnsuccessfulLogin(5, user.getUserName(), "");

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(false);
        alteredAccountStatus.setLocked(false);

        updateAccountStatus(user, alteredAccountStatus)
                .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId(), IdentityZoneHolder.get().getId()));

        attemptLogin(user)
                .andExpect(redirectedUrl("/login?error=account_locked"));
    }

    @Test
    void testGetUser() throws Exception {
        getUser(scimReadWriteToken, HttpStatus.OK.value());
    }

    @Test
    void testGetUserWithInvalidAttributes() throws Exception {

        String nonexistentAttribute = "displayBlaBla";

        MockHttpServletRequestBuilder get = get("/Users")
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .contentType(MediaType.APPLICATION_JSON)
                .param("attributes", nonexistentAttribute)
                .accept(APPLICATION_JSON);

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        String body = mvcResult.getResponse().getContentAsString();

        List<Map> attList = (List) JsonUtils.readValue(body, Map.class).get("resources");
        for (Map<String, Object> attMap : attList) {
            assertNull(attMap.get(nonexistentAttribute));
        }
    }

    @Test
    void testGetUserWithScimCreateToken() throws Exception {
        getUser(scimCreateToken, HttpStatus.FORBIDDEN.value());
    }

    @Test
    void getUsersWithUaaAdminToken() throws Exception {
        setUpScimUser();

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users")
                .header("Authorization", "Bearer " + uaaAdminToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isOk());

    }

    @Test
    void getUserFromOtherZoneWithUaaAdminToken() throws Exception {
        IdentityZone otherIdentityZone = getIdentityZone();

        ScimUser user = setUpScimUser(otherIdentityZone);

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/", user.getId())
                .header("Authorization", "Bearer " + uaaAdminToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isOk());

    }

    @Test
    void testUpdateUser() throws Exception {
        updateUser(scimReadWriteToken, HttpStatus.OK.value());
    }

    @Nested
    @DefaultTestContext
    class WhenSelfEditing {
        private ZoneSeeder zoneSeeder;

        @BeforeEach
        void setup(ZoneSeeder zoneSeeder) {
            this.zoneSeeder = zoneSeeder.withDefaults().withDisableInternalUserManagement(false);
        }

        @Nested
        @DefaultTestContext
        class WhenAnAdminSelfEdits {
            private ScimUser adminUser;
            private ClientDetails adminClient;

            @BeforeEach
            void beforeEach() {
                zoneSeeder.withClientWithImplicitPasswordRefreshTokenGrants("admin_client", "uaa.admin,scim.write")
                        .withUserWhoBelongsToGroups("admin@test.org", Lists.newArrayList("uaa.admin", "scim.write"))
                        .afterSeeding(zs -> {
                            adminUser = zs.getUserByEmail("admin@test.org");
                            adminClient = zs.getClientById("admin_client");
                        });
            }

            @Test
            void put_usingAnAccessTokenWithScimWriteScope_aUserCanSelfUpdateAnything() throws Exception {
                performSelfEdit_shouldSucceed("scim.write", put("/Users/" + adminUser.getId()));
            }

            @Test
            void put_usingAnAccessTokenWithUaaAdminScope_aUserCanSelfUpdateAnything() throws Exception {
                performSelfEdit_shouldSucceed("uaa.admin", put("/Users/" + adminUser.getId()));
            }

            @Test
            void patch_usingAnAccessTokenWithScimWriteScope_aUserCanSelfUpdateAnything() throws Exception {
                performSelfEdit_shouldSucceed("scim.write", patch("/Users/" + adminUser.getId()));
            }

            @Test
            void patch_usingAnAccessTokenWithUaaAdminScope_aUserCanSelfUpdateAnything() throws Exception {
                performSelfEdit_shouldSucceed("uaa.admin", patch("/Users/" + adminUser.getId()));
            }

            private void performSelfEdit_shouldSucceed(String scopesToBeIncludedInToken, MockHttpServletRequestBuilder requestBuilder) throws Exception {
                String accessToken = testClient.getUserOAuthAccessTokenForZone(
                        adminClient.getClientId(),
                        zoneSeeder.getPlainTextClientSecret(adminClient),
                        adminUser.getUserName(),
                        zoneSeeder.getPlainTextPassword(adminUser),
                        scopesToBeIncludedInToken,
                        zoneSeeder.getIdentityZoneSubdomain()
                );

                String newAdminUsername = "newAdminUsername";
                adminUser.setUserName(newAdminUsername);

                mockMvc.perform(requestBuilder
                        .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                        .header("Authorization", "Bearer " + accessToken)
                        .header("If-Match", "\"" + adminUser.getVersion() + "\"")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsBytes(adminUser)))
                        .andDo(print())
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.userName").value(newAdminUsername));
            }
        }

        @Nested
        @DefaultTestContext
        class WhenARegularUserSelfEdits {
            private ScimUser regularUser;

            @BeforeEach
            void beforeEach() {
                ScimUser user = zoneSeeder.newRandomScimUser();
                user.addPhoneNumber("initial phone number");
                user.setName(new ScimUser.Name("initial given name", "initial family name"));
                user.setPrimaryEmail("initialEmail@test.org");

                zoneSeeder.withClientWithImplicitPasswordRefreshTokenGrants()
                        .withUser(user)
                        .afterSeeding(zs -> {
                            regularUser = zs.getUserByEmail("initialEmail@test.org");
                        });
            }

            @Test
            void put_updateUserEmail_WithAccessToken_ShouldFail() throws Exception {
                String accessToken = getAccessTokenForUser(regularUser);

                String newEmail = "otheruser@" + generator.generate().toLowerCase() + ".com";
                regularUser.setEmails(null);
                regularUser.addEmail(newEmail);

                MockHttpServletRequestBuilder put = put("/Users/" + regularUser.getId())
                        .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                        .header("Authorization", "Bearer " + accessToken)
                        .header("If-Match", "\"" + regularUser.getVersion() + "\"")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsBytes(regularUser));

                mockMvc.perform(put).andDo(print())
                        .andExpect(status().is(403))
                        .andExpect(jsonPath("$.error", is("invalid_self_edit")))
                        .andExpect(jsonPath("$.error_description", is(
                                "Users are only allowed to edit their own User settings when internal user storage is enabled, " +
                                        "and in that case they may only edit the givenName and familyName.")
                        ));
            }

            @Test
            void patch_selfUpdate_WithAccessToken_WhenTryingToDeleteAField_shouldResultIn403() throws Exception {
                test_patch_selfUpdate_WithAccessToken(
                        "{\"meta\": {\"attributes\": [\"phonenumbers\"]}}",
                        403, "$.error", "invalid_self_edit"
                );
            }

            @Test
            void patch_selfUpdate_WithAccessToken_WhenFamilyNameAndGivenNameAreChanged_shouldResultIn200() throws Exception {
                test_patch_selfUpdate_WithAccessToken(
                        "{\"name\": {\"givenName\": \"newGivenName\", \"familyName\": \"newFamilyName\"}}",
                        200, "$.name.givenName", "newGivenName");
            }

            @Test
            void patch_selfUpdate_WithAccessToken_WhenPrimaryEmailIsChanged_shouldResultIn403() throws Exception {
                String newEmail = "otheruser@" + RandomStringUtils.randomAlphabetic(5) + ".com";

                test_patch_selfUpdate_WithAccessToken(
                        "{\"emails\": " +
                                "  [" +
                                "    {\n" +
                                "        \"value\" : \"" + newEmail + "\",\n" +
                                "        \"primary\" : true\n" +
                                "    } " +
                                "  ]" +
                                "}",
                        403, "$.error", "invalid_self_edit");
            }

            void test_patch_selfUpdate_WithAccessToken(String patchRequestBody, int expectedHttpStatusCode, String expectedJsonPath, String expectedValueAtJsonPath) throws Exception {
                String accessToken = getAccessTokenForUser(regularUser);

                MockHttpServletRequestBuilder patch = patch("/Users/" + regularUser.getId())
                        .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                        .header("Authorization", "Bearer " + accessToken)
                        .header("If-Match", "\"" + regularUser.getVersion() + "\"")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(patchRequestBody.getBytes());

                mockMvc.perform(patch)
                        .andDo(print())
                        .andExpect(status().is(expectedHttpStatusCode))
                        .andExpect(jsonPath(expectedJsonPath).value(expectedValueAtJsonPath));
            }

            private String getAccessTokenForUser(ScimUser scimUser) throws Exception {
                return testClient.getUserOAuthAccessTokenForZone(
                        zoneSeeder.getClientWithImplicitPasswordRefreshTokenGrants().getClientId(),
                        zoneSeeder.getPlainTextClientSecret(zoneSeeder.getClientWithImplicitPasswordRefreshTokenGrants()),
                        scimUser.getUserName(),
                        zoneSeeder.getPlainTextPassword(scimUser),
                        "openid",
                        zoneSeeder.getIdentityZoneSubdomain());
            }

            @Nested
            @DefaultTestContext
            class WithInternalUserStoreDisabled {

                @BeforeEach
                void beforeEach() {
                    zoneSeeder.withDisableInternalUserManagement(true);
                }

                @Test
                void put_updateNothing_shouldFail() throws Exception {
                    mockMvc.perform(put("/Users/" + regularUser.getId())
                            .headers(zoneSeeder.getZoneIdRequestHeader())
                            .header("Authorization", "Bearer " + uaaAdminToken)
                            .header("If-Match", "\"" + regularUser.getVersion() + "\"")
                            .accept(APPLICATION_JSON)
                            .contentType(APPLICATION_JSON)
                            .content(JsonUtils.writeValueAsBytes(regularUser)))
                            .andDo(print())
                            .andExpect(status().is(403))
                            .andExpect(content().string(JsonObjectMatcherUtils.matchesJsonObject(
                                    new JSONObject()
                                            .put("error_description", "Internal User Creation is currently disabled. External User Store is in use.")
                                            .put("message", "Internal User Creation is currently disabled. External User Store is in use.")
                                            .put("error", "internal_user_management_disabled"))));
                }

                @Test
                void put_updateUserEmail_WithAccessToken_ShouldFail() throws Exception {
                    String accessToken = getAccessTokenForUser(WhenARegularUserSelfEdits.this.regularUser);

                    regularUser.setEmails(null);
                    regularUser.addEmail("resetEmail@mail.com");

                    MockHttpServletRequestBuilder put = put("/Users/" + regularUser.getId())
                            .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                            .header("Authorization", "Bearer " + accessToken)
                            .header("If-Match", "\"" + regularUser.getVersion() + "\"")
                            .accept(APPLICATION_JSON)
                            .contentType(APPLICATION_JSON)
                            .content(JsonUtils.writeValueAsBytes(regularUser));
                    mockMvc.perform(put).andDo(print())
                            .andExpect(status().is(403))
                            .andExpect(content().string(JsonObjectMatcherUtils.matchesJsonObject(
                                    new JSONObject()
                                            .put("error_description", "Internal User Creation is currently disabled. External User Store is in use.")
                                            .put("message", "Internal User Creation is currently disabled. External User Store is in use.")
                                            .put("error", "internal_user_management_disabled"))));
                }

                @Test
                void patch_updateUserEmail_WithAccessToken_ShouldFail() throws Exception {
                    String accessToken = getAccessTokenForUser(WhenARegularUserSelfEdits.this.regularUser);

                    regularUser.addEmail("addAnotherNew@email.com");

                    MockHttpServletRequestBuilder patch = patch("/Users/" + regularUser.getId())
                            .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                            .header("Authorization", "Bearer " + accessToken)
                            .header("If-Match", "\"" + regularUser.getVersion() + "\"")
                            .accept(APPLICATION_JSON)
                            .contentType(APPLICATION_JSON)
                            .content(JsonUtils.writeValueAsBytes(regularUser));
                    mockMvc.perform(patch)
                            .andExpect(status().is(403))
                            .andExpect(content().string(JsonObjectMatcherUtils.matchesJsonObject(
                                    new JSONObject()
                                            .put("error_description", "Internal User Creation is currently disabled. External User Store is in use.")
                                            .put("message", "Internal User Creation is currently disabled. External User Store is in use.")
                                            .put("error", "internal_user_management_disabled"))));
                }
            }
        }
    }

    @Test
    void testUpdateUser_No_Username_Returns_400() throws Exception {
        updateUser(scimReadWriteToken, HttpStatus.BAD_REQUEST.value());
    }

    @Test
    void testUpdateUserWithScimCreateToken() throws Exception {
        updateUser(scimCreateToken, HttpStatus.FORBIDDEN.value());
    }

    @Test
    void testUpdateUserWithUaaAdminToken() throws Exception {
        updateUser(uaaAdminToken, HttpStatus.OK.value());
    }

    @Test
    void testUpdateUserInOtherZoneWithUaaAdminToken() throws Exception {
        IdentityZone identityZone = getIdentityZone();
        ScimUser user = setUpScimUser(identityZone);
        user.setName(new ScimUser.Name("changed", "name"));

        mockMvc.perform(put("/Users/" + user.getId())
                .header("Authorization", "Bearer " + uaaAdminToken)
                .header(HEADER, identityZone.getId())
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user)))
                .andExpect(status().isOk())
                .andExpect(header().string("ETag", "\"1\""))
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()));
    }

    @Test
    void delete_user_clears_approvals() throws Exception {
        ApprovalStore store = webApplicationContext.getBean(ApprovalStore.class);
        JdbcTemplate template = webApplicationContext.getBean(JdbcTemplate.class);
        ScimUser user = setUpScimUser();

        Approval approval = new Approval();
        approval.setClientId("cf");
        approval.setUserId(user.getId());
        approval.setScope("openid");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        store.addApproval(approval, IdentityZoneHolder.get().getId());
        assertEquals(1, (long) template.queryForObject("select count(*) from authz_approvals where user_id=?", Integer.class, user.getId()));
        mockMvc.perform((delete("/Users/" + user.getId()))
                .header("Authorization", "Bearer " + uaaAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()));
        assertEquals(0, (long) template.queryForObject("select count(*) from authz_approvals where user_id=?", Integer.class, user.getId()));
    }

    @Test
    void testDeleteUserWithUaaAdminToken() throws Exception {
        ScimUser user = setUpScimUser();
        mockMvc.perform((delete("/Users/" + user.getId()))
                .header("Authorization", "Bearer " + uaaAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()));
    }

    @Test
    void testDeleteUserInOtherZoneWithUaaAdminToken() throws Exception {
        IdentityZone identityZone = getIdentityZone();
        ScimUser user = setUpScimUser(identityZone);

        mockMvc.perform((delete("/Users/" + user.getId()))
                .header("Authorization", "Bearer " + uaaAdminToken)
                .header(HEADER, identityZone.getId())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()));
    }

    @Test
    void cannotCreateUserWithInvalidPasswordInDefaultZone() throws Exception {
        ScimUser user = getScimUser();
        user.setPassword(new RandomValueStringGenerator(260).generate());
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + scimCreateToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_password"))
                .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."));
    }

    @Test
    void testCreateUserWithEmailDomainNotAllowedForOriginUaa() throws Exception {
        ScimUser user = new ScimUser(null, "abc@example.org", "First", "Last");
        user.addEmail("abc@example.org");
        user.setPassword(new RandomValueStringGenerator(2).generate());
        user.setOrigin("uaa");
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        IdentityProvider oidcProvider = new IdentityProvider().setActive(true).setName("OIDC_test").setType(OriginKeys.OIDC10).setOriginKey(OriginKeys.OIDC10).setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.setIdentityZoneId(IdentityZoneHolder.getUaaZone().getId());
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.org"));

        identityProviderProvisioning.create(oidcProvider, oidcProvider.getIdentityZoneId());
        try {
            MockHttpServletRequestBuilder post = post("/Users")
                    .header("Authorization", "Bearer " + scimCreateToken)
                    .contentType(APPLICATION_JSON)
                    .content(requestBody);

            mockMvc.perform(post)
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("The user account is set up for single sign-on. Please use one of these origin(s) : [oidc1.0]"));
        } finally {
            identityProviderProvisioning.deleteByOrigin(oidcProvider.getOriginKey(), IdentityZoneHolder.getUaaZone().getId());
        }
    }

    @Test
    void testDeleteMfaUserCredentials() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        MfaProvider provider = createMfaProvider(IdentityZoneHolder.get().getId());
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(true).setProviderName("mfaProvider"));
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials(user.getId(), "ABCDEFGHIJKLMNOP", 1234, Arrays.asList(123456)).setMfaProviderId(provider.getId());
        mfaCredentialsProvisioning.save(creds, IdentityZoneHolder.get().getId());

        assertNotNull(mfaCredentialsProvisioning.retrieve(user.getId(), provider.getId()));

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId() + "/mfa")
                .header("Authorization", "Bearer " + uaaAdminToken)
                .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
                .andExpect(status().isOk());

        assertMfaCredentialsNotExisting(user, provider);
    }

    @Test
    void testDeleteMfaUserCredentialsWithZoneSwitching() throws Exception {
        IdentityZone identityZone = getIdentityZone();
        String authorities = "zones." + identityZone.getId() + ".admin";
        clientDetails = MockMvcUtils.createClient(mockMvc, uaaAdminToken, "switchClientId", "switchClientSecret", null, null, Collections.singletonList("client_credentials"), authorities, null, IdentityZone.getUaa());
        String uaaAdminTokenFromOtherZone = testClient.getClientCredentialsOAuthAccessToken("switchClientId", "switchClientSecret", authorities);
        ScimUser user = setUpScimUser(identityZone);
        MfaProvider provider = createMfaProvider(identityZone.getId());
        identityZone.getConfig().setMfaConfig(new MfaConfig().setEnabled(true).setProviderName("mfaProvider"));
        MockMvcUtils.updateIdentityZone(identityZone, webApplicationContext);
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials(user.getId(), "ABCDEFGHIJKLMNOP", 1234, Arrays.asList(123456)).setMfaProviderId(provider.getId());
        mfaCredentialsProvisioning.save(creds, identityZone.getId());

        assertNotNull(mfaCredentialsProvisioning.retrieve(user.getId(), provider.getId()));

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId() + "/mfa")
                .header("Authorization", "Bearer " + uaaAdminTokenFromOtherZone)
                .header(HEADER, identityZone.getId())
                .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
                .andExpect(status().isOk());

        assertMfaCredentialsNotExisting(user, provider);
    }

    @Test
    void testDeleteMfaUserCredentialsNotAuthorized() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId() + "/mfa")
                .header("Authorization", "Bearer " + scimCreateToken)
                .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
                .andExpect(status().isForbidden());
    }

    @Test
    void testDeleteMfaUserCredentialsUserDoesNotExist() throws Exception {
        MfaProvider provider = createMfaProvider(IdentityZoneHolder.get().getId());
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(true).setProviderName("mfaProvider"));
        String userId = "invalidUserId";

        MockHttpServletRequestBuilder delete = delete("/Users/" + userId + "/mfa")
                .header("Authorization", "Bearer " + uaaAdminToken)
                .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
                .andExpect(status().isNotFound());

        try {
            mfaCredentialsProvisioning.retrieve(userId, provider.getId());
            fail();
        } catch (UserMfaConfigDoesNotExistException e) {
            //no op
        }
    }

    @Test
    void testDeleteMfaUserCredentialsUserNotRegistered() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        MfaProvider provider = createMfaProvider(IdentityZoneHolder.get().getId());
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(true).setProviderName("mfaProvider"));

        assertMfaCredentialsNotExisting(user, provider);

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId() + "/mfa")
                .header("Authorization", "Bearer " + uaaAdminToken)
                .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
                .andExpect(status().isOk());

        assertMfaCredentialsNotExisting(user, provider);
    }

    @Test
    void testDeleteMfaUserCredentialsMfaNotEnabled() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        MfaProvider provider = createMfaProvider(IdentityZoneHolder.get().getId());
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(false));
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials(user.getId(), "ABCDEFGHIJKLMNOP", 1234, Arrays.asList(123456)).setMfaProviderId(provider.getId());
        mfaCredentialsProvisioning.save(creds, IdentityZoneHolder.get().getId());

        assertNotNull(mfaCredentialsProvisioning.retrieve(user.getId(), provider.getId()));

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId() + "/mfa")
                .header("Authorization", "Bearer " + uaaAdminToken)
                .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
                .andExpect(status().isOk());

        assertMfaCredentialsNotExisting(user, provider);
    }

    private MfaProvider createMfaProvider(String identityZoneId) {
        String index = generator.generate();
        String mfaProviderId = "mfaProviderId" + index;
        String mfaProviderName = "mfaProvider" + index;
        MfaProvider provider = new MfaProvider().setName(mfaProviderName).setId(mfaProviderId).setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR).setConfig(new GoogleMfaProviderConfig()).setIdentityZoneId(identityZoneId);
        mfaProviderProvisioning.create(provider, identityZoneId);
        return provider;
    }

    private void assertMfaCredentialsNotExisting(ScimUser user, MfaProvider provider) {
        try {
            mfaCredentialsProvisioning.retrieve(user.getId(), provider.getId());
            fail();
        } catch (UserMfaConfigDoesNotExistException e) {
            //no op
        }
    }

    private MockHttpServletRequestBuilder setUpVerificationLinkRequest(ScimUser user, String token) {
        return MockMvcRequestBuilders.get("/Users/" + user.getId() + "/verify-link")
                .header("Authorization", "Bearer " + token)
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);
    }

    private ScimUser setUpScimUser() {
        return setUpScimUser(IdentityZoneHolder.get());
    }

    private ScimUser setUpScimUser(IdentityZone zone) {
        IdentityZone original = IdentityZoneHolder.get();
        try {
            IdentityZoneHolder.set(zone);
            String email = "joe@" + generator.generate().toLowerCase() + ".com";
            ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
            joel.setVerified(false);
            joel.addEmail(email);
            joel = usersRepository.createUser(joel, USER_PASSWORD, IdentityZoneHolder.get().getId());
            return joel;
        } finally {
            IdentityZoneHolder.set(original);
        }
    }

    private String getQueryStringParam(String query, String key) {
        List<NameValuePair> params = URLEncodedUtils.parse(query, Charset.defaultCharset());
        for (NameValuePair pair : params) {
            if (key.equals(pair.getName())) {
                return pair.getValue();
            }
        }
        return null;
    }

    private IdentityZone getIdentityZone() throws Exception {
        String subdomain = generator.generate();
        return MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());
    }

    private ScimUser createUser(String token) throws Exception {
        return createUser(token, null);
    }

    private ScimUser createUser(String token, String subdomain) throws Exception {
        return createUser(getScimUser(), token, subdomain);
    }

    private ScimUser createUser(ScimUser user, String token, String subdomain) throws Exception {
        return createUser(user, token, subdomain, null);
    }

    private ScimUser createUser(ScimUser user, String token, String subdomain, String switchZone) throws Exception {
        String password = hasText(user.getPassword()) ? user.getPassword() : "pas5word";
        user.setPassword(password);
        MvcResult result = createUserAndReturnResult(user, token, subdomain, switchZone)
                .andExpect(status().isCreated())
                .andExpect(header().string("ETag", "\"0\""))
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getUserName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andReturn();
        user = JsonUtils.readValue(result.getResponse().getContentAsString(), ScimUser.class);
        user.setPassword(password);
        return user;
    }

    private ResultActions createUserAndReturnResult(ScimUser user, String token, String subdomain, String switchZone) throws Exception {
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        if (subdomain != null && !subdomain.equals(""))
            post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        if (switchZone != null) post.header(HEADER, switchZone);

        return mockMvc.perform(post);
    }

    private ScimUser getScimUser() {
        String email = "joe@" + generator.generate().toLowerCase() + ".com";
        ScimUser user = new ScimUser();
        user.setUserName(email);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail(email);
        return user;
    }

    private ScimUser updateUser(String token, int status) throws Exception {
        ScimUserProvisioning usersRepository = webApplicationContext.getBean(ScimUserProvisioning.class);
        String email = "otheruser@" + generator.generate().toLowerCase() + ".com";
        ScimUser user = new ScimUser(null, email, "Other", "User");
        user.addEmail(email);
        user = usersRepository.createUser(user, "pas5Word", IdentityZoneHolder.get().getId());
        if (status == HttpStatus.BAD_REQUEST.value()) {
            user.setUserName(null);
        } else {
            String username2 = "ou" + generator.generate().toLowerCase();
            user.setUserName(username2);
        }

        user.setName(new ScimUser.Name("Joe", "Smith"));

        return updateUser(token, status, user);
    }

    private ScimUser updateUser(String token, int status, ScimUser user) throws Exception {
        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
                .header("Authorization", "Bearer " + token)
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user));
        if (status == HttpStatus.OK.value()) {
            String json = mockMvc.perform(put)
                    .andExpect(status().isOk())
                    .andExpect(header().string("ETag", "\"1\""))
                    .andExpect(jsonPath("$.userName").value(user.getUserName()))
                    .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                    .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                    .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
                    .andReturn().getResponse().getContentAsString();

            return JsonUtils.readValue(json, ScimUser.class);
        } else {
            mockMvc.perform(put)
                    .andExpect(status().is(status));
            return null;
        }
    }

    private ResultActions updateAccountStatus(ScimUser user, UserAccountStatus alteredAccountStatus) throws Exception {
        String jsonStatus = JsonUtils.writeValueAsString(alteredAccountStatus);
        return mockMvc
                .perform(
                        patch("/Users/" + user.getId() + "/status")
                                .header("Authorization", "Bearer " + uaaAdminToken)
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_JSON)
                                .content(jsonStatus)
                );
    }

    private ResultActions attemptLogin(ScimUser user) throws Exception {
        return mockMvc
                .perform(post("/login.do")
                        .with(cookieCsrf())
                        .param("username", user.getUserName())
                        .param("password", user.getPassword()));
    }

    private void attemptUnsuccessfulLogin(int numberOfAttempts, String username, String subdomain) throws Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder post = post("/login.do")
                .with(new SetServerNameRequestPostProcessor(requestDomain))
                .with(cookieCsrf())
                .param("username", username)
                .param("password", "wrong_password");
        for (int i = 0; i < numberOfAttempts; i++) {
            mockMvc.perform(post)
                    .andExpect(redirectedUrl("/login?error=login_failure"));
        }
    }

    private void verifyUser(String token) throws Exception {
        ScimUserProvisioning usersRepository = webApplicationContext.getBean(ScimUserProvisioning.class);
        String email = "joe@" + generator.generate().toLowerCase() + ".com";
        ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
        joel.addEmail(email);
        joel = usersRepository.createUser(joel, "pas5Word", IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(header().string("ETag", "\"0\""))
                .andExpect(jsonPath("$.userName").value(email))
                .andExpect(jsonPath("$.emails[0].value").value(email))
                .andExpect(jsonPath("$.name.familyName").value("D'sa"))
                .andExpect(jsonPath("$.name.givenName").value("Joel"))
                .andExpect(jsonPath("$.verified").value(true));
    }

    private void getUser(String token, int status) throws Exception {
        ScimUser joel = setUpScimUser();

        getAndReturnUser(status, joel, token);
    }

    private ScimUser getAndReturnUser(int status, ScimUser user, String token) throws Exception {
        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + user.getId())
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON);

        if (status == HttpStatus.OK.value()) {
            String json = mockMvc.perform(get)
                    .andExpect(status().is(status))
                    .andExpect(header().string("ETag", "\"" + user.getVersion() + "\""))
                    .andExpect(jsonPath("$.userName").value(user.getPrimaryEmail()))
                    .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                    .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
                    .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                    .andReturn().getResponse().getContentAsString();
            return JsonUtils.readValue(json, ScimUser.class);
        } else {
            mockMvc.perform(get)
                    .andExpect(status().is(status));
            return null;
        }
    }

    private void performAuthentication(ScimUser user, boolean success) throws Exception {
        mockMvc.perform(
                post("/login.do")
                        .accept("text/html")
                        .with(cookieCsrf())
                        .param("username", user.getUserName())
                        .param("password", USER_PASSWORD))
                .andDo(print())
                .andExpect(success ? authenticated() : unauthenticated());
    }
}
