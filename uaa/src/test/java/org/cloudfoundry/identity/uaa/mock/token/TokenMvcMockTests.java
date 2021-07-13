package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.httpclient.util.URIUtil;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.OAuthToken;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenRevokedException;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static java.util.Collections.emptySet;
import static org.cloudfoundry.identity.uaa.mock.util.JwtTokenUtils.getClaimsForToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setDisableInternalAuth;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REFRESH_TOKEN_SUFFIX;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.createLocalSamlIdpDefinition;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.SCOPE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestPropertySource(properties = {"uaa.url=https://localhost:8080/uaa"})
public class TokenMvcMockTests extends AbstractTokenMockMvcTests {
    private String BADSECRET = "badsecret";
    protected RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private static SamlTestUtils samlTestUtils = new SamlTestUtils();

    @BeforeAll
    static void initializeSamlUtils() {
        samlTestUtils.initializeSimple();
    }

    @BeforeEach
    void setup() {
        webApplicationContext.getEnvironment();
        IdentityZoneHolder.setProvisioning(webApplicationContext.getBean(IdentityZoneProvisioning.class));
    }

    @AfterEach
    void resetRefreshTokenCreator() {
        RefreshTokenCreator bean = webApplicationContext.getBean(RefreshTokenCreator.class);
        bean.setRestrictRefreshGrant(false);
    }

    @Test
    void token_endpoint_get_by_default() throws Exception {
        try_token_with_non_post(get("/oauth/token"), status().isOk(), APPLICATION_JSON_UTF8_VALUE);
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {
            "jwt.token.queryString.enabled=false"
    })
    class WithDisallowedQueryString {

        @Autowired
        private MockMvc mockMvc;

        private String username;

        @BeforeEach
        void setUp(
                final @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning,
                final @Autowired JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
                final @Autowired JdbcScimGroupProvisioning jdbcScimGroupProvisioning) {
            username = createUserForPasswordGrant(
                    jdbcScimUserProvisioning,
                    jdbcScimGroupMembershipManager,
                    jdbcScimGroupProvisioning,
                    generator);
        }

        @Test
        void token_endpoint_get() throws Exception {
            mockMvc.perform(
                    get("/oauth/token")
                            .param("client_id", "cf")
                            .param("client_secret", "")
                            .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                            .param("username", username)
                            .param("password", SECRET)
                            .accept(APPLICATION_JSON)
                            .contentType(APPLICATION_FORM_URLENCODED))
                    .andDo(print())
                    .andExpect(status().isMethodNotAllowed())
                    .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE))
                    .andExpect(jsonPath("$.error").value("method_not_allowed"))
                    .andExpect(jsonPath("$.error_description").value("Request method 'GET' not supported"));
        }

        @Test
        void token_endpoint_post_query_string() throws Exception {
            mockMvc.perform(
                    post("/oauth/token?client_id=cf&client_secret=&grant_type=password&username={username}&password=secret", username)
                            .accept(APPLICATION_JSON)
                            .contentType(APPLICATION_FORM_URLENCODED))
                    .andExpect(status().isNotAcceptable())
                    .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE))
                    .andExpect(jsonPath("$.error").value("query_string_not_allowed"))
                    .andExpect(jsonPath("$.error_description").value("Parameters must be passed in the body of the request"));
        }
    }

    @Test
    void token_endpoint_put() throws Exception {
        try_token_with_non_post(put("/oauth/token"), status().isMethodNotAllowed(), APPLICATION_JSON_VALUE)
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'PUT' not supported"));

    }

    @Test
    void token_endpoint_delete() throws Exception {
        try_token_with_non_post(delete("/oauth/token"), status().isMethodNotAllowed(), APPLICATION_JSON_VALUE)
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'DELETE' not supported"));

    }

    @Test
    void token_endpoint_post() throws Exception {
        try_token_with_non_post(post("/oauth/token"), status().isOk(), APPLICATION_JSON_UTF8_VALUE);
    }

    @Test
    void token_endpoint_post_query_string_by_default() throws Exception {
        String username = createUserForPasswordGrant(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator);

        mockMvc.perform(
                post("/oauth/token?client_id=cf&client_secret=&grant_type=password&username={username}&password=secret", username)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk());
    }

    @Test
    void refresh_grant_fails_because_missing_required_groups() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "password,refresh_token", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetailsService.addClientDetails(clientDetails);
        MvcResult result = doPasswordGrant(username, SECRET, clientId, SECRET, status().isOk());

        Map<String, Object> tokenResponse = JsonUtils.readValue(
                result.getResponse().getContentAsString(),
                new TypeReference<Map<String, Object>>() {
                }
        );

        String refreshToken = (String) tokenResponse.get(REFRESH_TOKEN);
        assertNotNull(refreshToken);

        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Collections.singletonList("uaa.admin"));
        clientDetailsService.updateClientDetails(clientDetails);

        result = doRefreshGrant(refreshToken, clientId, SECRET, status().isUnauthorized());
        assertThat(result.getResponse().getContentAsString(), containsString("User does not meet the client's required group criteria."));
    }

    @Test
    void authorization_code_missing_required_scopes() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource", "http://localhost");
        clientDetails.setClientSecret(SECRET);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Collections.singletonList("uaa.admin"));
        clientDetailsService.addClientDetails(clientDetails);

        String location = mockMvc.perform(
                get("/oauth/authorize")
                        .param(RESPONSE_TYPE, "code")
                        .param(CLIENT_ID, clientId)
                        .session(getAuthenticatedSession(user))
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andReturn().getResponse().getHeader("Location");
        assertThat(location, containsString("http://localhost"));
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUri(new URI(location)).build().getQueryParams();
        assertNotNull(queryParams);
        assertNotNull(queryParams.getFirst("error"));
        assertNotNull(queryParams.getFirst("error_description"));
        assertThat(
                queryParams.getFirst("error_description"),
                containsString(UriUtils.encodeQueryParam("User does not meet the client's required group criteria.", "ISO-8859-1"))
        );
    }

    @Test
    void authorization_code_missing_required_scopes_during_token_fetch() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource", "http://localhost");
        clientDetails.setAutoApproveScopes(Collections.singletonList("true"));
        clientDetails.setClientSecret(SECRET);
        clientDetailsService.addClientDetails(clientDetails);

        String location = mockMvc.perform(
                get("/oauth/authorize")
                        .param(RESPONSE_TYPE, "code")
                        .param(CLIENT_ID, clientId)
                        .param(SCOPE, "openid")
                        .session(getAuthenticatedSession(user))
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andReturn().getResponse().getHeader("Location");
        assertThat(location, containsString("http://localhost"));
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUri(new URI(location)).build().getQueryParams();
        assertNotNull(queryParams);
        String code = queryParams.getFirst("code");
        assertNotNull(code);

        //adding required user groups
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Collections.singletonList("uaa.admin"));
        clientDetailsService.updateClientDetails(clientDetails);

        MvcResult result = mockMvc.perform(
                post("/oauth/token")
                        .param("code", code)
                        .param("client_id", clientId)
                        .param("client_secret", SECRET)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isUnauthorized())
                .andReturn();

        Map<String, Object> errorResponse = JsonUtils.readValue(
                result.getResponse().getContentAsString(),
                new TypeReference<Map<String, Object>>() {
                }
        );

        assertThat((String) errorResponse.get("error_description"), containsString("User does not meet the client's required group criteria."));
    }

    @Test
    void token_grant_missing_required_groups() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "password", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Collections.singletonList("uaa.admin"));
        clientDetailsService.addClientDetails(clientDetails);
        MvcResult result = doPasswordGrant(username, SECRET, clientId, SECRET, status().isBadRequest());
        Map<String, Object> errorResponse = JsonUtils.readValue(
                result.getResponse().getContentAsString(),
                new TypeReference<Map<String, Object>>() {
                }
        );

        assertThat((String) errorResponse.get("error_description"), containsString("User does not meet the client's required group criteria."));
    }

    @Test
    void token_grant_required_groups_are_present() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,required.scope.1,required.scope.2";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope,required.scope.1,required.scope.2", "password", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("required.scope.1", "required.scope.2"));
        clientDetailsService.addClientDetails(clientDetails);
        doPasswordGrant(username, SECRET, clientId, SECRET, status().isOk());
    }

    @Test
    void password_grant() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertEquals(1, webApplicationContext.getBean(JdbcTemplate.class).update("UPDATE users SET passwd_change_required = ? WHERE ID = ?", true, user.getId()));
        doPasswordGrant(username, SECRET, "cf", "", status().is4xxClientError());
    }

    @Test
    void test_logon_timestamps_with_password_grant() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        ScimUserProvisioning provisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        ScimUser scimUser = provisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
        assertNull(scimUser.getLastLogonTime());
        assertNull(scimUser.getPreviousLogonTime());

        doPasswordGrant(username, SECRET, "cf", "", status().isOk());
        scimUser = provisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
        assertNotNull(scimUser.getLastLogonTime());
        assertNull(scimUser.getPreviousLogonTime());

        long lastLogonTime = scimUser.getLastLogonTime();
        doPasswordGrant(username, SECRET, "cf", "", status().isOk());
        scimUser = provisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
        assertNotNull(scimUser.getLastLogonTime());
        assertNotNull(scimUser.getPreviousLogonTime());
        assertEquals(lastLogonTime, (long) scimUser.getPreviousLogonTime());
        assertTrue(scimUser.getLastLogonTime() > scimUser.getPreviousLogonTime());

    }

    @Test
    void passcode_with_client_parameters_when_password_change_required_for_user() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        jdbcScimUserProvisioning.updatePasswordChangeRequired(user.getId(), true, IdentityZoneHolder.get().getId());

        String response = mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", "cf")
                        .param("client_secret", "")
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        Map<String, String> error = (JsonUtils.readValue(response, new TypeReference<Map<String, String>>() {
        }));
        String error_description = error.get("error_description");
        assertNotNull(error_description);
        assertEquals("password change required", error_description);

    }

    @Test
    void passcode_with_client_parameters() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String content = mockMvc.perform(
                get("/passcode")
                        .session(getAuthenticatedSession(user))
                        .accept(APPLICATION_JSON)
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String code = JsonUtils.readValue(content, String.class);

        String response = mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", "cf")
                        .param("client_secret", "")
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("passcode", code)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });
        Object accessToken = tokens.get(ACCESS_TOKEN);
        Object jti = tokens.get(JTI);
        assertNotNull(accessToken);
        assertNotNull(jti);
    }

    @Test
    void test_encoded_char_on_authorize_url() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        mockMvc.perform(
                get("/oauth/authorize")
                        .param("client_id", new String(new char[]{'\u0000'}))
                        .session(getAuthenticatedSession(user))
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isBadRequest())
                .andExpect(request().attribute("error_message_code", "request.invalid_parameter"));
    }

    @Test
    void refresh_access_token_and_user_group_removed() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user,uaa.admin", "password,refresh_token", true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,uaa.admin";
        ScimUser scimUser = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String response = mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("client_secret", SECRET)
                .param("username", username)
                .param("password", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });
        String scopes = (String) tokens.get(SCOPE);
        assertThat(scopes, containsString("uaa.admin"));
        Object refreshToken = tokens.get(REFRESH_TOKEN);
        String refreshTokenId = (String) refreshToken;

        List<ScimGroup> groups = webApplicationContext.getBean(ScimGroupProvisioning.class).query("displayName eq \"uaa.admin\"", IdentityZoneHolder.get().getId());
        assertEquals(1, groups.size());
        webApplicationContext.getBean(ScimGroupMembershipManager.class).removeMemberById(groups.get(0).getId(), scimUser.getId(), IdentityZoneHolder.get().getId());

        mockMvc.perform(
                post("/oauth/token")
                        .with(httpBasic(clientId, SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.RESPONSE_TYPE, "token")
                        .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                        .param(REFRESH_TOKEN, refreshTokenId)
                        .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue()))

                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
    }


    @Test
    void test_token_ids() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "password,refresh_token", true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String response = mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("client_secret", SECRET)
                .param("username", username)
                .param("password", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });
        Object accessToken = tokens.get(ACCESS_TOKEN);
        Object refreshToken = tokens.get(REFRESH_TOKEN);
        Object jti = tokens.get(JTI);
        assertNotNull(accessToken);
        assertNotNull(refreshToken);
        assertNotNull(jti);
        assertEquals(jti, accessToken);
        assertNotEquals(accessToken + REFRESH_TOKEN_SUFFIX, refreshToken);
        String accessTokenId = (String) accessToken;
        String refreshTokenId = (String) refreshToken;

        response = mockMvc.perform(
                post("/oauth/token")
                        .with(httpBasic(clientId, SECRET))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                        .param(REFRESH_TOKEN, refreshTokenId)
                        .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue()))

                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });
        accessToken = tokens.get(ACCESS_TOKEN);
        refreshToken = tokens.get(REFRESH_TOKEN);
        jti = tokens.get(JTI);
        assertNotNull(accessToken);
        assertNotNull(refreshToken);
        assertNotNull(jti);
        assertEquals(jti, accessToken);
        assertNotEquals(accessToken + REFRESH_TOKEN_SUFFIX, refreshToken);
        assertNotEquals(accessToken, accessTokenId);
        assertEquals(accessToken, jti);
        assertNotEquals(refreshToken, jti);
    }

    @Test
    void test_saml_bearer_grant() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        //all our SAML defaults use :8080/uaa/ so we have to use that here too
        String host = subdomain + ".localhost";
        String fullPath = "/uaa/oauth/token/alias/" + subdomain + ".cloudfoundry-saml-login";
        String origin = subdomain + ".cloudfoundry-saml-login";

        MockMvcUtils.IdentityZoneCreationResult zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain,
                mockMvc,
                webApplicationContext,
                null,
                false, IdentityZoneHolder.getCurrentZoneId());

        //create an actual IDP, so we can fetch metadata
        String idpMetadata = MockMvcUtils.getIDPMetaData(mockMvc, subdomain);

        //create an IDP in the default zone
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(origin, zone.getIdentityZone().getId(), idpMetadata);
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getIdentityZone().getId());
        provider.setName(origin);
        provider.setOriginKey(origin);

        IdentityZoneHolder.set(zone.getIdentityZone());
        webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).create(provider, provider.getIdentityZoneId());
        IdentityZoneHolder.clear();

        String assertion = samlTestUtils.mockAssertionEncoded(subdomain + ".cloudfoundry-saml-login",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "Saml2BearerIntegrationUser",
                "http://" + subdomain + ".localhost:8080/uaa/oauth/token/alias/" + subdomain + ".cloudfoundry-saml-login",
                subdomain + ".cloudfoundry-saml-login"
        );

        //create client in default zone
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.none", "uaa.user,openid", GRANT_TYPE_SAML2_BEARER + ",password", true, TEST_REDIRECT_URI, null, 600, zone.getIdentityZone());


        //String fullPath = "/uaa/oauth/token";
        MockHttpServletRequestBuilder post = post(fullPath)
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(fullPath);
                    request.setServerName(host);
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, host)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", clientId)
                .param("client_secret", "secret")
                .param("assertion", assertion);


        mockMvc.perform(post)
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid uaa.user"));

        mockMvc.perform(post.param("scope", "uaa.admin"))
                .andDo(print())
                .andExpect(status().isBadRequest());

    }

    @Test
    void test_two_zone_saml_bearer_grant() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        //all our SAML defaults use :8080/uaa/ so we have to use that here too
        String spInvocationEndpoint = "/uaa/oauth/token/alias/cloudfoundry-saml-login";
        String idpOrigin = subdomain + ".cloudfoundry-saml-login";

        //create an zone - that zone will be our IDP
        MockMvcUtils.IdentityZoneCreationResult zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain,
                mockMvc,
                webApplicationContext,
                null,
                false, IdentityZoneHolder.getCurrentZoneId());
        //create an actual IDP, so we can fetch metadata
        String spMetadata = MockMvcUtils.getSPMetadata(mockMvc, null);
        String idpMetadata = MockMvcUtils.getIDPMetaData(mockMvc, subdomain);

        //create an IDP in the default zone
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(idpOrigin, IdentityZone.getUaaZoneId(), idpMetadata);
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(IdentityZone.getUaaZoneId());
        provider.setName(idpOrigin);
        provider.setOriginKey(idpOrigin);

        IdentityZoneHolder.clear();
        webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).create(provider, provider.getIdentityZoneId());
        IdentityZoneHolder.clear();

        String assertion = samlTestUtils.mockAssertionEncoded(subdomain + ".cloudfoundry-saml-login",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "Saml2BearerIntegrationUser",
                "http://localhost:8080/uaa/oauth/token/alias/cloudfoundry-saml-login",
                "cloudfoundry-saml-login"
        );

        //create client in default zone
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.none", "uaa.user,openid", GRANT_TYPE_SAML2_BEARER + ",password", true, TEST_REDIRECT_URI, null, 600, null);


        MockHttpServletRequestBuilder post = post(spInvocationEndpoint)
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(spInvocationEndpoint);
                    request.setServerName("localhost");
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, "localhost")
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer")
                .param("client_id", clientId)
                .param("client_secret", "secret")
                .param("assertion", assertion);


        String json = mockMvc.perform(post)
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid uaa.user"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        mockMvc.perform(post.param("scope", "uaa.admin"))
                .andDo(print())
                .andExpect(status().isBadRequest());

    }

    @Test
    void getOauthToken_Password_Grant_When_UAA_Provider_is_Disabled() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "password", true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        setDisableInternalAuth(webApplicationContext, IdentityZone.getUaaZoneId(), true);
        try {
            mockMvc.perform(post("/oauth/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .param(OAuth2Utils.GRANT_TYPE, "password")
                    .param(OAuth2Utils.CLIENT_ID, clientId)
                    .param("client_secret", SECRET)
                    .param("username", username)
                    .param("password", SECRET))
                    .andExpect(status().isUnauthorized());
        } finally {
            setDisableInternalAuth(webApplicationContext, IdentityZone.getUaaZoneId(), false);
        }
    }

    @Test
    void token_endpoint_should_return_Basic_WWW_Authenticate_Header() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", GRANT_TYPE_AUTHORIZATION_CODE, true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        MockHttpSession session = getAuthenticatedSession(developer);
        String state = generator.generate();
        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isFound())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);

        assertThat(code.length(), greaterThan(9));

        state = ((List<String>) query.get("state")).get(0);

        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("code", code)
                .param("state", state))
                .andExpect(status().isUnauthorized())
                .andExpect(
                        header()
                                .stringValues("WWW-Authenticate",
                                        "Basic realm=\"UAA/client\", error=\"unauthorized\", error_description=\"Bad credentials\"")
                );
    }

    @Test
    void getOauthToken_usingAuthCode_withClientIdAndSecretInRequestBody_shouldBeOk() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", GRANT_TYPE_AUTHORIZATION_CODE, true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isFound())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);

        assertThat(code.length(), greaterThan(9));

        state = ((List<String>) query.get("state")).get(0);

        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", "secret")
                .param("code", code)
                .param("state", state))
                .andExpect(status().isOk());
    }

    @Test
    void testRefreshTokenNotPresentWhenClientDoesNotHaveGrantType() throws Exception {
        BaseClientDetails clientWithoutRefreshTokenGrant = setUpClients("testclient" + generator.generate(), "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, true);
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        MockHttpSession session = getAuthenticatedSession(developer);

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.CLIENT_ID, clientWithoutRefreshTokenGrant.getClientId()))
                .andExpect(status().isFound())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.CLIENT_ID, clientWithoutRefreshTokenGrant.getClientId())
                .param("client_secret", "secret")
                .param("code", code);

        MvcResult mvcResult = mockMvc.perform(oauthTokenPost).andReturn();
        assertNotNull(JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), Map.class).get("access_token"));
        assertNull(JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), Map.class).get("refresh_token"));
    }

    @Test
    void refreshAccessToken_withClient_withAutoApproveField() throws Exception {
        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Collections.singletonList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isFound())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);
        state = ((List<String>) query.get("state")).get(0);

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", "secret")
                .param("code", code)
                .param("state", state);

        MvcResult mvcResult = mockMvc.perform(oauthTokenPost).andReturn();
        OAuth2RefreshToken refreshToken = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), CompositeToken.class).getRefreshToken();

        MockHttpServletRequestBuilder postForRefreshToken = post("/oauth/token")
                .with(httpBasic(clientId, SECRET))
                .param(GRANT_TYPE, REFRESH_TOKEN)
                .param(REFRESH_TOKEN, refreshToken.getValue());
        mockMvc.perform(postForRefreshToken).andExpect(status().isOk());
    }

    @Test
    void authorizeEndpointWithPromptNone_WhenNotAuthenticated() throws Exception {
        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Collections.singletonList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        MockHttpSession session = new MockHttpSession();

        String state = generator.generate();

        MvcResult result = mockMvc.perform(
                get("/oauth/authorize")
                        .session(session)
                        .param(OAuth2Utils.RESPONSE_TYPE, "code")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                        .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andExpect(status().isFound())
                .andReturn();

        String url = result.getResponse().getHeader("Location");
        assertTrue(url.startsWith(UaaUrlUtils.addQueryParameter(TEST_REDIRECT_URI, "error", "login_required")));
    }

    @Test
    void testAuthorizeEndpointWithPromptNone_MfaRequired() throws Exception {
        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Collections.singletonList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        super.setupForMfaPasswordGrant(developer.getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();

        String url = result.getResponse().getHeader("Location");
        assertTrue(url.startsWith(UaaUrlUtils.addQueryParameter(TEST_REDIRECT_URI, "error", "interaction_required")));

        setAuthentication(session, developer, false, "mfa", "pwd", "otp");
        result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();
        url = result.getResponse().getHeader("Location");
        assertThat(url, containsString(TEST_REDIRECT_URI));
        assertThat(url, not(containsString("error")));
        assertThat(url, not(containsString("login_required")));
        assertThat(url, not(containsString("interaction_required")));
    }

    @Test
    void testAuthorizeEndpointWithPromptNone_ForcePasswordChangeRequired() throws Exception {
        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Collections.singletonList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer, true, "pwd", "mfa", "otp");

        String state = generator.generate();

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();

        String url = result.getResponse().getHeader("Location");
        assertTrue(url.startsWith(UaaUrlUtils.addQueryParameter(TEST_REDIRECT_URI, "error", "interaction_required")));

        setAuthentication(session, developer, false, "mfa", "pwd", "otp");
        result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();
        url = result.getResponse().getHeader("Location");
        assertThat(url, containsString(TEST_REDIRECT_URI));
        assertThat(url, not(containsString("error")));
        assertThat(url, not(containsString("login_required")));
        assertThat(url, not(containsString("interaction_required")));
    }

    @Test
    void testAuthorizeEndpointWithPromptNone_Authenticated() throws Exception {
        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Collections.singletonList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andExpect(status().isFound())
                .andReturn();

        String url = result.getResponse().getHeader("Location");
        assertThat(url, containsString(TEST_REDIRECT_URI));
    }

    @Test
    void getOauthToken_usingPassword_withClientIdAndSecretInRequestBody_shouldBeOk() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "password", true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", username)
                .param("password", SECRET))
                .andExpect(status().isOk());
    }

    @Test
    void getOauthToken_usingPassword_withNoCommonScopes_shouldBeUnauthorized() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "something_else", "password", true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        MvcResult result = mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", username)
                .param("password", SECRET))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getContentAsString(), containsString("[something_else] is invalid. This user is not allowed any of the requested scopes"));
    }

    @Test
    void getOauthToken_usingClientCredentials_withClientIdAndSecretInRequestBody_shouldBeOk() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "client_credentials", true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "client_credentials")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk());
    }

    @Test
    void testClientIdentityProviderWithoutAllowedProvidersForPasswordGrantWorksInOtherZone() throws Exception {
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        //a client without allowed providers in non default zone should always be rejected
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider(OriginKeys.UAA);

        String clientId2 = "testclient" + generator.generate();
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI,
                Collections.singletonList(provider.getOriginKey()));

        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        String username = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, testZone.getId());

        mockMvc.perform(post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isOk());

        mockMvc.perform(post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId2, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId2))
                .andExpect(status().isOk());


    }

    @Test
    void getToken_withPasswordGrantType_resultsInUserLastLogonTimestampUpdate() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());

        String accessToken = getAccessTokenForPasswordGrant(username);
        Long firstTimestamp = getPreviousLogonTime(accessToken);

        String accessToken2 = getAccessTokenForPasswordGrant(username);
        Long secondTimestamp = getPreviousLogonTime(accessToken2);

        assertNotEquals(firstTimestamp, secondTimestamp);
        assertTrue(firstTimestamp < secondTimestamp);
    }

    private String getAccessTokenForPasswordGrant(String username) throws Exception {
        String response = mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", "cf")
                        .param("client_secret", "")
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return (String) JsonUtils.readValue(response, Map.class).get("access_token");
    }

    private Long getPreviousLogonTime(String accessToken) throws Exception {
        UserInfoResponse userInfo;
        String userInfoResponse = mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "bearer " + accessToken)
                        .accept(APPLICATION_JSON)
        ).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        assertNotNull(userInfoResponse);
        userInfo = JsonUtils.readValue(userInfoResponse, UserInfoResponse.class);
        return userInfo.getPreviousLogonSuccess();
    }

    @Test
    void testClientIdentityProviderClientWithoutAllowedProvidersForAuthCodeAlreadyLoggedInWorksInAnotherZone() throws Exception {
        //a client without allowed providers in non default zone should always be rejected
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider(OriginKeys.UAA);

        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        String clientId2 = "testclient" + generator.generate();
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI,
                Collections.singletonList(provider.getOriginKey()));

        String clientId3 = "testclient" + generator.generate();
        setUpClients(clientId3, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI,
                Collections.singletonList(OriginKeys.LOGIN_SERVER));

        String username = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, testZone.getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        IdentityZoneHolder.clear();

        //no providers is ok
        mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isFound());

        //correct provider is ok
        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId2)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isFound())
                .andReturn();

        //other provider, not ok
        mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId3)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isUnauthorized())
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attribute("error_message_code", "login.invalid_idp"));


        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);

    }

    @Test
    void testClientIdentityProviderRestrictionForPasswordGrant() throws Exception {
        //a client with allowed providers in the default zone should be rejected if the client is not allowed
        String clientId = "testclient" + generator.generate();
        String clientId2 = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        String idpOrigin = "origin-" + generator.generate();
        IdentityProvider provider = setupIdentityProvider(idpOrigin);

        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI,
                Collections.singletonList(provider.getOriginKey()));
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        //create a user in the UAA identity provider
        String username = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());


        mockMvc.perform(post("/oauth/token")
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/oauth/token")
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId2, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId2))
                .andExpect(status().isOk());
    }

    @Test
    void test_OAuth_Authorize_API_Endpoint() throws Exception {
        String subdomain = "testzone" + generator.generate().toLowerCase();
        IdentityZone testZone = setupIdentityZone(subdomain, new ArrayList<>(defaultAuthorities));
        IdentityZoneHolder.set(testZone);

        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "openid,uaa.user,scim.me";
        setUpClients(clientId, "", scopes, "authorization_code,password,refresh_token", true);

        String username = "testuser" + generator.generate();
        String userScopes = "";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        String uaaUserAccessToken = getUserOAuthAccessToken(
                mockMvc,
                clientId,
                SECRET,
                username,
                SECRET,
                "",
                testZone
        );

        String state = generator.generate();

        MockHttpServletRequestBuilder oauthAuthorizeGet = get("/oauth/authorize")
                .header("Authorization", "Bearer " + uaaUserAccessToken)
                .header("Host", subdomain + ".localhost")
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId);
        MvcResult result = mockMvc.perform(oauthAuthorizeGet).andExpect(status().is3xxRedirection()).andReturn();

        String location = result.getResponse().getHeader("Location");
        assertNotNull("Location must be present", location);
        assertThat("Location must have a code parameter.", location, containsString("code="));

        URL url = new URL(location);
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);

        String body = mockMvc.perform(post("/oauth/token")
                .with(httpBasic(clientId, SECRET))
                .header("Host", subdomain + ".localhost")
                .accept(APPLICATION_JSON)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("code", code))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // zone context needs to be set again because MVC calls mutate it
        IdentityZoneHolder.set(testZone);

        assertNotNull("Token body must not be null.", body);
        assertThat(body, stringContainsInOrder(Arrays.asList(ACCESS_TOKEN, REFRESH_TOKEN)));
        Map<String, Object> map = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        String accessToken = (String) map.get("access_token");
        OAuth2Authentication token = tokenServices.loadAuthentication(accessToken);
        assertTrue("Must have uaa.user scope", token.getOAuth2Request().getScope().contains("uaa.user"));
    }

    @Test
    void refreshTokenIssued_whenScopeIsPresent_andRestrictedOnGrantType() throws Exception {
        RefreshTokenCreator bean = webApplicationContext.getBean(RefreshTokenCreator.class);
        bean.setRestrictRefreshGrant(true);
        String clientId = "testclient" + generator.generate();
        String scopes = "openid,uaa.user,scim.me,uaa.offline_token";
        setUpClients(clientId, "", scopes, "password,refresh_token", true);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.offline_token";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .param("username", username)
                .param("password", SECRET)
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password");
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get("access_token"));
        assertNotNull(token.get(REFRESH_TOKEN));
    }

    @Test
    void refreshAccessToken_whenScopeIsPresent_andRestrictedOnGrantType() throws Exception {
        RefreshTokenCreator bean = webApplicationContext.getBean(RefreshTokenCreator.class);
        bean.setRestrictRefreshGrant(true);
        String clientId = "testclient" + generator.generate();
        String scopes = "openid,uaa.user,scim.me,uaa.offline_token";
        setUpClients(clientId, "", scopes, "password,refresh_token", true);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.offline_token";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .param("username", username)
                .param("password", SECRET)
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password");
        MvcResult mvcResult = mockMvc.perform(oauthTokenPost).andReturn();
        OAuth2RefreshToken refreshToken = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), CompositeToken.class).getRefreshToken();

        MockHttpServletRequestBuilder postForRefreshToken = post("/oauth/token")
                .with(httpBasic(clientId, SECRET))
                .param(GRANT_TYPE, REFRESH_TOKEN)
                .param(REFRESH_TOKEN, refreshToken.getValue());
        mockMvc.perform(postForRefreshToken).andExpect(status().isOk());


        mockMvc.perform(postForRefreshToken.param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())).andExpect(status().isOk());
        mockMvc.perform(postForRefreshToken.param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())).andExpect(status().isOk());
    }

    @Test
    void testOpenIdTokenHybridFlowWithNoImplicitGrant_When_IdToken_Disabled() throws Exception {
        try {
            webApplicationContext.getBean(DisableIdTokenResponseTypeFilter.class).setIdTokenDisabled(true);

            String clientId = "testclient" + generator.generate();
            String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
            setUpClients(clientId, scopes, scopes, GRANT_TYPE_AUTHORIZATION_CODE, true);
            String username = "testuser" + generator.generate();
            String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
            ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

            MockHttpSession session = getAuthenticatedSession(developer);

            String state = generator.generate();

            MockHttpServletRequestBuilder oauthTokenPost = get("/oauth/authorize")
                    .session(session)
                    .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                    .param(SCOPE, "openid")
                    .param(OAuth2Utils.STATE, state)
                    .param(OAuth2Utils.CLIENT_ID, clientId)
                    .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

            MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
            String location = result.getResponse().getHeader("Location");
            assertFalse(location.contains("#"));
            URL url = new URL(location);
            Map query = splitQuery(url);
            assertNotNull(query.get("code"));
            assertNull(query.get("id_token"));
            String code = ((List<String>) query.get("code")).get(0);
            assertNotNull(code);
        } finally {
            webApplicationContext.getBean(DisableIdTokenResponseTypeFilter.class).setIdTokenDisabled(false);
        }
    }

    @Test
    void testOpenIdTokenHybridFlowWithNoImplicitGrant() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPE_AUTHORIZATION_CODE, true);
        String username = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MockHttpServletRequestBuilder oauthTokenPost = get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        assertTrue(location.contains("#"));
        URL url = new URL(location.replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        assertNotNull(((List) query.get("id_token")).get(0));
        assertNotNull(((List) query.get("code")).get(0));
        assertNull(query.get("token"));
    }

    @Test
    void prompt_is_none_and_approvals_are_required() throws Exception {
        String redirectUrl = TEST_REDIRECT_URI + "#test=true";
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "implicit,authorization_code", false);
        String username = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = new RandomValueStringGenerator().generate();

        mockMvc.perform(
                post("/oauth/authorize")
                        .session(session)
                        .param(OAuth2Utils.RESPONSE_TYPE, "token")
                        .param("prompt", "none")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.REDIRECT_URI, redirectUrl)
                        .with(cookieCsrf())
        )
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", startsWith(redirectUrl)))
                .andExpect(header().string("Location", containsString("error=interaction_required")));
    }

    @Test
    void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenLenientWhenAppNotApproved() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPE_AUTHORIZATION_CODE, false);
        String username = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setClientId(clientId);
        authorizationRequest.setRedirectUri(TEST_REDIRECT_URI);
        authorizationRequest.setScope(new ArrayList<>(Collections.singletonList("openid")));
        authorizationRequest.setResponseTypes(new TreeSet<>(Arrays.asList("code", "id_token")));
        authorizationRequest.setState(state);

        session.setAttribute(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        session.setAttribute(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, unmodifiableMap(authorizationRequest));

        MvcResult result = mockMvc.perform(
                post("/oauth/authorize")
                        .session(session)
                        .with(cookieCsrf())
                        .param(OAuth2Utils.USER_OAUTH_APPROVAL, "true")
                        .param("scope.0", "scope.openid")
        ).andExpect(status().is3xxRedirection()).andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);
    }

    @Test
    void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenStrictWhenAppNotApproved() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPE_AUTHORIZATION_CODE, false);
        String username = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setClientId(clientId);
        authorizationRequest.setRedirectUri(TEST_REDIRECT_URI);
        authorizationRequest.setScope(new ArrayList<>(Collections.singletonList("openid")));
        authorizationRequest.setResponseTypes(new TreeSet<>(Arrays.asList("code", "id_token")));
        authorizationRequest.setState(state);
        session.setAttribute(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, authorizationRequest);
        session.setAttribute(UaaAuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST, unmodifiableMap(authorizationRequest));

        MvcResult result = mockMvc.perform(
                post("/oauth/authorize")
                        .session(session)
                        .param(OAuth2Utils.USER_OAUTH_APPROVAL, "true")
                        .with(cookieCsrf())
                        .param("scope.0", "scope.openid")
        ).andExpect(status().is3xxRedirection()).andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("id_token"));
        assertNotNull(((List) query.get("id_token")).get(0));
        assertNotNull(((List) query.get("code")).get(0));
        assertNull(query.get("token"));
    }

    @Test
    void test_subdomain_redirect_url() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";
        String subDomainUri = redirectUri.replace("example.com", "test.example.com");
        String clientId = "authclient-" + generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser" + generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .with(httpBasic(clientId, SECRET))
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, subDomainUri);

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        location = location.substring(0, location.indexOf("&code="));
        assertEquals(subDomainUri, location);
    }

    @Test
    void invalidScopeErrorMessageIsNotShowingAllClientScopes() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPE_AUTHORIZATION_CODE, true);

        String username = "testuser" + generator.generate();
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, "scim.write", OriginKeys.UAA, IdentityZoneHolder.getUaaZone().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .with(httpBasic(clientId, SECRET))
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "scim.write")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult mvcResult = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();

        UriComponents locationComponents = UriComponentsBuilder.fromUri(URI.create(mvcResult.getResponse().getHeader("Location"))).build();
        MultiValueMap<String, String> queryParams = locationComponents.getQueryParams();
        String errorMessage = URIUtil.encodeQuery("scim.write is invalid. Please use a valid scope name in the request");
        assertFalse(queryParams.containsKey("scope"));
        assertEquals(errorMessage, queryParams.getFirst("error_description"));
    }

    @Test
    void invalidScopeErrorMessageIsNotShowingAllUserScopes() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "openid,password.write,cloud_controller.read,scim.userids,password.write,something.else";
        setUpClients(clientId, scopes, scopes, GRANT_TYPE_AUTHORIZATION_CODE, true);

        String username = "testuser" + generator.generate();
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, "openid", OriginKeys.UAA, IdentityZoneHolder.getUaaZone().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .with(httpBasic(clientId, SECRET))
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "something.else")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult mvcResult = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();

        UriComponents locationComponents = UriComponentsBuilder.fromUri(URI.create(mvcResult.getResponse().getHeader("Location"))).build();
        MultiValueMap<String, String> queryParams = locationComponents.getQueryParams();
        String errorMessage = URIUtil.encodeQuery("[something.else] is invalid. This user is not allowed any of the requested scopes");
        assertFalse(queryParams.containsKey("scope"));
        assertEquals(errorMessage, queryParams.getFirst("error_description"));
    }

    @Test
    void ensure_that_form_redirect_is_not_a_parameter_unless_there_is_a_saved_request() throws Exception {
        //make sure we don't create a session on the homepage
        assertNull(
                mockMvc.perform(
                        get("/login")
                )
                        .andDo(print())
                        .andExpect(content().string(not(containsString(FORM_REDIRECT_PARAMETER))))
                        .andReturn().getRequest().getSession(false));

        //if there is a session, but no saved request
        mockMvc.perform(
                get("/login")
                        .session(new MockHttpSession())
        )
                .andDo(print())
                .andExpect(content().string(not(containsString(FORM_REDIRECT_PARAMETER))));
    }

    @Test
    void test_authorization_code_grant_session_expires_during_app_approval() throws Exception {
        String username = "authuser" + generator.generate();
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, "", OriginKeys.UAA, IdentityZoneHolder.get().getId());

        String redirectUri = "http://localhost:8080/app/";
        String clientId = "authclient-" + generator.generate();
        String scopes = "openid,password.write,cloud_controller.read,scim.userids,password.write";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, false, redirectUri);


        String state = generator.generate();

        String url = UriComponentsBuilder
                .fromUriString("/oauth/authorize?response_type=code&scope=openid&state={state}&client_id={clientId}&redirect_uri={redirectUri}")
                .buildAndExpand(state, clientId, redirectUri)
                .encode()
                .toUri()
                .toString();

        MockHttpSession session = getAuthenticatedSession(user);

        MvcResult result = mockMvc
                .perform(get(new URI(url))
                        .session(session))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/oauth/confirm_access"))
                .andExpect(model().attribute("original_uri", "http://localhost" + url))
                .andReturn();
    }

    @Test
    void test_authorization_code_grant_redirect_when_session_expires() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";

        String clientId = "authclient-" + generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser" + generator.generate();
        String userScopes = "openid";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String state = generator.generate();

        String authUrl = "http://localhost" + UriComponentsBuilder
                .fromUriString("/oauth/authorize?response_type=code&scope=openid&state={state}&client_id={clientId}&redirect_uri={redirectUri}")
                .buildAndExpand(state, clientId, redirectUri)
                .encode()
                .toUri()
                .toString();

        String encodedRedirectUri = UriUtils.encodeQueryParam(redirectUri, "ISO-8859-1");

        MvcResult result = mockMvc
                .perform(get(new URI(authUrl)))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location, endsWith("/login"));

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        assertNotNull(savedRequest);
        assertEquals(authUrl, savedRequest.getRedirectUrl());

        mockMvc.perform(
                get("/login")
                        .session(session)
        )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(FORM_REDIRECT_PARAMETER)))
                .andExpect(content().string(containsString(encodedRedirectUri)));

        //a failed login should survive the flow
        //attempt to login without a session
        result = mockMvc.perform(
                post("/login.do")
                        .with(cookieCsrf())
                        .param("form_redirect_uri", authUrl)
                        .param("username", username)
                        .param("password", "invalid")
        )
                .andExpect(status().isFound())
                .andExpect(header().string("Location", containsString("/login")))
                .andReturn();

        session = (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session);
        savedRequest =  SessionUtils.getSavedRequestSession(session);
        assertNotNull(savedRequest);

        mockMvc.perform(
                get("/login")
                        .session(session)
        )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(FORM_REDIRECT_PARAMETER)))
                .andExpect(content().string(containsString(encodedRedirectUri)));

        //attempt to login without a session
        mockMvc.perform(
                post("/login.do")
                        .with(cookieCsrf())
                        .param("form_redirect_uri", authUrl)
                        .param("username", username)
                        .param("password", SECRET)
        )
                .andExpect(status().isFound())
                .andExpect(header().string("Location", authUrl));
    }

    @Test
    void test_missing_redirect_uri() throws Exception {

        test_invalid_registered_redirect_uris(emptySet(), status().isBadRequest());
    }

    @Test
    void test_invalid_redirect_uri() throws Exception {
        test_invalid_registered_redirect_uris(new HashSet(Arrays.asList("*", "*/*")), status().isBadRequest());
    }

    @Test
    void test_valid_redirect_uri() throws Exception {
        String redirectUri = "https://example.com/**";
        test_invalid_registered_redirect_uris(new HashSet(Collections.singletonList(redirectUri)), status().isFound());
    }

    @Test
    void testAuthorizationCodeGrantWithEncodedRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=%7B%22orgGuid%22%3A%22org-guid%22%2C%22spaceGuid%22%3A%22space-guid%22%2C%22appGuid%22%3A%22app-guid%22%2C%22redirect%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D";
        //String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";
        String clientId = "authclient-" + generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser" + generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        location = location.substring(0, location.indexOf("&code="));
        assertEquals(redirectUri, location);
    }

    @Test
    void make_sure_Bootstrapped_users_Dont_Revoke_Tokens_If_No_Change() throws Exception {
        String tokenString = mockMvc.perform(post("/oauth/token")
                .param("username", "testbootuser")
                .param("password", "password")
                .with(httpBasic("cf", ""))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> tokenResponse = JsonUtils.readValue(tokenString, new TypeReference<Map<String, Object>>() {
        });
        String accessToken = (String) tokenResponse.get("access_token");

        //ensure we can do scim.read
        mockMvc.perform(get("/Users")
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
        ).andExpect(status().isOk());

        //ensure we can do scim.read with the existing token
        mockMvc.perform(get("/Users")
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
        ).andExpect(status().isOk());
    }

    @Test
    void testAuthorizationCode_ShouldNot_Throw_500_If_Client_Doesnt_Exist() throws Exception {
        String redirectUri = "https://example.com/";
        String clientId = "nonexistent-" + generator.generate();
        String userScopes = "openid";

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .accept(MediaType.TEXT_HTML)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                .param(SCOPE, userScopes)
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");

        HttpSession session = result.getRequest().getSession(false);

        MockHttpServletRequestBuilder login = get("/login")
                .accept(MediaType.TEXT_HTML)
                .session((MockHttpSession) session);
        mockMvc.perform(login).andExpect(status().isOk());
    }

    @Test
    void testImplicitGrantWithFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid#test";
        testImplicitGrantRedirectUri(redirectUri, false);
    }

    @Test
    void testImplicitGrantWithNoFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        testImplicitGrantRedirectUri(redirectUri, false);
    }

    @Test
    void testImplicitGrantWithFragmentInRedirectURLAndNoPrompt() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid#test";
        testImplicitGrantRedirectUri(redirectUri, true);
    }

    @Test
    void testImplicitGrantWithNoFragmentInRedirectURLAndNoPrompt() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        testImplicitGrantRedirectUri(redirectUri, true);
    }

    @Test
    void testWildcardRedirectURL() throws Exception {
        String state = generator.generate();
        String clientId = "authclient-" + generator.generate();
        String scopes = "openid";
        String redirectUri = "http*://subdomain.domain.com/**/path2?query1=value1";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser" + generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        MockHttpSession session = getAuthenticatedSession(developer);


        String requestedUri = "https://subdomain.domain.com/path1/path2?query1=value1";
        ResultMatcher status = status().is3xxRedirection();
        performAuthorize(state, clientId, "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())), session, requestedUri, status);
        requestedUri = "http://subdomain.domain.com/path1/path2?query1=value1";
        performAuthorize(state, clientId, "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())), session, requestedUri, status);
        requestedUri = "http://subdomain.domain.com/path1/path1a/path1b/path2?query1=value1";
        performAuthorize(state, clientId, "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())), session, requestedUri, status);
        requestedUri = "https://wrongsub.domain.com/path1/path2?query1=value1";
        status = status().is4xxClientError();
        performAuthorize(state, clientId, "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())), session, requestedUri, status);
        requestedUri = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
        status = status().is4xxClientError();
        performAuthorize(state, clientId, "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())), session, requestedUri, status);

    }

    @Test
    void gettingOpenIdToken_withPasswordGrantType_usingBasicAuth() throws Exception {
        String clientId = "password-grant-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "password,refresh_token", true);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("username", developer.getUserName())
                .param("password", SECRET)
                .param(SCOPE, "openid");

        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get(ACCESS_TOKEN));
        assertNotNull(token.get(REFRESH_TOKEN));
        assertNotNull(token.get("id_token"));
        assertNotEquals(token.get(ACCESS_TOKEN), token.get("id_token"));
        validateOpenIdConnectToken((String) token.get("id_token"), developer.getId(), clientId);
    }

    @Test
    void gettingOpenIdToken_withPasswordGrantType_withoutBasicAuth() throws Exception {
        String clientId = "password-grant-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "password,refresh_token", true);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());

        MvcResult result = mockMvc.perform(post("/oauth/token")
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED)
                .header(ACCEPT, "application/json")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("username", developer.getUserName())
                .param("password", SECRET)
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param(SCOPE, "openid"))
                .andExpect(status().isOk())
                .andReturn();

        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get(ACCESS_TOKEN));
        assertNotNull(token.get(REFRESH_TOKEN));
        assertNotNull(token.get("id_token"));
        assertNotEquals(token.get(ACCESS_TOKEN), token.get("id_token"));
        validateOpenIdConnectToken((String) token.get("id_token"), developer.getId(), clientId);
    }

    @Test
    void legacyUserAuthentication_IdTokenRequest() throws Exception {
        String clientId = "implicit-grant-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "implicit,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());

        //request for id_token using our old-style direct authentication
        //this returns a redirect with a fragment in the URL/Location header
        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", developer.getUserName(), SECRET);
        MvcResult result = mockMvc.perform(post("/oauth/authorize")
                .header("Accept", "application/json")
                .param(OAuth2Utils.RESPONSE_TYPE, "token id_token")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param("credentials", credentials)
                .param(OAuth2Utils.STATE, "random-state")
                .param(SCOPE, "openid"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertNotNull(hashFragmentParams.get("access_token").get(0));
        assertNotNull(hashFragmentParams.get("id_token").get(0));
        assertNotEquals(hashFragmentParams.get("access_token").get(0), hashFragmentParams.get("id_token").get(0));
        validateOpenIdConnectToken(hashFragmentParams.get("id_token").get(0), developer.getId(), clientId);
    }

    @Test
    void gettingOpenIdToken_withAuthorizationCodeGrantType_withBasicAuth() throws Exception {
        String clientId = "authcode-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "authorization_code,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);
        String state = "random-state";

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(ClaimConstants.NONCE, "testnonce")
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location"));
        Map<String, List<String>> authorizeRedirectQueryParams = splitQuery(url);
        String returnedState = authorizeRedirectQueryParams.get(OAuth2Utils.STATE).get(0);
        assertEquals(state, returnedState);
        String code = authorizeRedirectQueryParams.get("code").get(0);
        assertNotNull(code);

        result = mockMvc.perform(post("/oauth/token")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(tokenResponse.get(ACCESS_TOKEN));
        assertNotNull(tokenResponse.get(REFRESH_TOKEN));
        assertNotNull(tokenResponse.get("id_token"));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), authorizeRedirectQueryParams.get("id_token"));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        //nonce must be in id_token if was in auth request, see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        assertEquals("testnonce", claims.get(ClaimConstants.NONCE));
    }

    @Test
    void gettingOpenIdToken_HybridFlow_withCodePlusTokenPlusIdToken() throws Exception {
        //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        String clientId = "hybrid-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "authorization_code,implicit,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);
        String state = "random-state";

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token token")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(ClaimConstants.NONCE, "testnonce")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertEquals("bearer", hashFragmentParams.get("token_type").get(0));
        assertNotNull(hashFragmentParams.get("access_token").get(0));
        assertNotNull(hashFragmentParams.get("id_token").get(0));
        assertNotNull(hashFragmentParams.get("code").get(0));
        assertEquals(state, hashFragmentParams.get("state").get(0));
        assertNotNull(hashFragmentParams.get("expires_in").get(0));
        assertEquals("testnonce", hashFragmentParams.get("nonce").get(0));
        assertNotNull(hashFragmentParams.get("jti").get(0));
        validateOpenIdConnectToken(hashFragmentParams.get("id_token").get(0), developer.getId(), clientId);
        String code = hashFragmentParams.get("code").get(0);

        result = mockMvc.perform(post("/oauth/token")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(tokenResponse.get(ACCESS_TOKEN));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), hashFragmentParams.get(ACCESS_TOKEN));
        assertNotNull(tokenResponse.get(REFRESH_TOKEN));
        assertNotNull(tokenResponse.get("id_token"));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), tokenResponse.get("id_token"));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertEquals("testnonce", claims.get(ClaimConstants.NONCE));
    }

    @Test
    void gettingOpenIdToken_HybridFlow_withCodePlusIdToken() throws Exception {
        String clientId = "hybrid-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "authorization_code,implicit,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);
        String state = "random-state";

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(ClaimConstants.NONCE, "testnonce")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertEquals("bearer", hashFragmentParams.get("token_type").get(0));
        assertNull(hashFragmentParams.get("access_token"));
        assertNotNull(hashFragmentParams.get("id_token").get(0));
        validateOpenIdConnectToken(hashFragmentParams.get("id_token").get(0), developer.getId(), clientId);
        assertNotNull(hashFragmentParams.get("code").get(0));
        assertEquals(state, hashFragmentParams.get("state").get(0));
        assertNotNull(hashFragmentParams.get("expires_in").get(0));
        assertEquals("testnonce", hashFragmentParams.get("nonce").get(0));
        assertNotNull(hashFragmentParams.get("jti").get(0));
        String code = hashFragmentParams.get("code").get(0);

        result = mockMvc.perform(post("/oauth/token")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(tokenResponse.get(ACCESS_TOKEN));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), hashFragmentParams.get(ACCESS_TOKEN));
        assertNotNull(tokenResponse.get(REFRESH_TOKEN));
        assertNotNull(tokenResponse.get("id_token"));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), tokenResponse.get("id_token"));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertEquals("testnonce", claims.get(ClaimConstants.NONCE));
    }

    @Test
    void gettingOpenIdToken_HybridFlow_withCodePlusToken() throws Exception {
        String clientId = "hybrid-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "authorization_code,implicit,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);
        String state = "random-state";

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code token")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(ClaimConstants.NONCE, "testnonce")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertEquals("bearer", hashFragmentParams.get("token_type").get(0));
        assertNotNull(hashFragmentParams.get("access_token").get(0));
        assertNull(hashFragmentParams.get("id_token"));
        assertNotNull(hashFragmentParams.get("code").get(0));
        assertEquals(state, hashFragmentParams.get("state").get(0));
        assertNotNull(hashFragmentParams.get("expires_in").get(0));
        assertEquals("testnonce", hashFragmentParams.get("nonce").get(0));
        assertNotNull(hashFragmentParams.get("jti").get(0));
        String code = hashFragmentParams.get("code").get(0);

        result = mockMvc.perform(post("/oauth/token")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(tokenResponse.get(ACCESS_TOKEN));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), hashFragmentParams.get(ACCESS_TOKEN));
        assertNotNull(tokenResponse.get(REFRESH_TOKEN));
        assertNotNull(tokenResponse.get("id_token"));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), tokenResponse.get("id_token"));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertEquals("testnonce", claims.get(ClaimConstants.NONCE));
    }

    @Test
    void gettingOpenIdToken_withAuthorizationCodeGrantType() throws Exception {
        String clientId = "authcode-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "authorization_code,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);
        String state = "random-state";

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(ClaimConstants.NONCE, "testnonce")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirectUri = result.getResponse().getHeader("Location");
        assertFalse("Redirect URL should not be a fragment.", redirectUri.contains("#"));
        assertTrue("Redirect URL should contain query params.", redirectUri.contains("?"));
        Map<String, List<String>> queryParams = splitQuery(new URL(redirectUri));
        assertEquals(state, queryParams.get("state").get(0));
        assertNotNull(queryParams.get("code").get(0));
        String code = queryParams.get("code").get(0);

        result = mockMvc.perform(post("/oauth/token")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .accept(APPLICATION_JSON)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param("code", code)
                .param(OAuth2Utils.STATE, state))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(tokenResponse.get(ACCESS_TOKEN));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), queryParams.get(ACCESS_TOKEN));
        assertNotNull(tokenResponse.get(REFRESH_TOKEN));
        // Successful OIDC token response should include ID Token even when scope=openid is not present.
        // http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        assertNotNull("ID Token should be present when client has openid scope", tokenResponse.get("id_token"));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), tokenResponse.get("id_token"));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertEquals("testnonce", claims.get(ClaimConstants.NONCE));
        assertEquals("openid", ((ArrayList<String>) getClaimsForToken(tokenResponse.get(ACCESS_TOKEN)).get("scope")).get(0));
    }

    @Test
    void attemptingToGetOpenIdToken_withAuthorizationCodeGrantType_whenClientMissingOpenidScope() throws Exception {
        String clientId = "authcode-client" + this.generator.generate();
        setUpClients(clientId, "", "not-openid,foo.read", "authorization_code,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "not-openid,foo.read", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);
        String state = "random-state";

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "not-openid foo.read")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirectUri = result.getResponse().getHeader("Location");
        assertFalse("Redirect URL should not be a fragment.", redirectUri.contains("#"));
        assertTrue("Redirect URL should contain query params.", redirectUri.contains("?"));
        Map<String, List<String>> queryParams = splitQuery(new URL(redirectUri));
        assertEquals(state, queryParams.get("state").get(0));
        assertNotNull(queryParams.get("code").get(0));
        String code = queryParams.get("code").get(0);

        result = mockMvc.perform(post("/oauth/token")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .accept(APPLICATION_JSON)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param("code", code)
                .param(OAuth2Utils.STATE, state))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(tokenResponse.get(ACCESS_TOKEN));
        assertNotEquals(tokenResponse.get(ACCESS_TOKEN), queryParams.get(ACCESS_TOKEN));
        assertEquals("not-openid", ((ArrayList<String>) getClaimsForToken(tokenResponse.get(ACCESS_TOKEN)).get("scope")).get(0));
        assertNotNull(tokenResponse.get(REFRESH_TOKEN));

        // Successful OIDC token response should include ID Token even when scope=openid is not present.
        // http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        assertNull("ID Token should not be present when client is missing openid scope", tokenResponse.get("id_token"));
    }

    @Test
    void gettingOpenIdToken_HybridFlow_withTokenPlusIdToken() throws Exception {
        //test if we can retrieve an ID token using
        //response type token+id_token after a regular auth_code flow
        String clientId = "hybrid-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "authorization_code,implicit,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);

        session = new MockHttpSession();
        setAuthentication(session, developer);

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, "random-state")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertNotNull(hashFragmentParams.get(OAuth2Utils.STATE));
        assertEquals("random-state", hashFragmentParams.get(OAuth2Utils.STATE).get(0));
        String code = hashFragmentParams.get("code").get(0);
        assertNotNull(code);

        result = mockMvc.perform(post("/oauth/token")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Basic "
                        + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param("code", code))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull("ID Token should be present when response_type includes id_token", tokenResponse.get("id_token"));
        assertNotNull(tokenResponse.get("id_token"));
        assertNotNull(tokenResponse.get("access_token"));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
    }

    @Test
    void gettingOpenIdToken_andNoAccessToken_withImplicitGrantType() throws Exception {
        String clientId = "implicit-client" + this.generator.generate();
        setUpClients(clientId, "", "openid", "implicit,refresh_token", true, TEST_REDIRECT_URI);
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "testuser" + this.generator.generate(), "openid", OriginKeys.UAA, IdentityZoneHolder.get().getId());
        logUserInTwice(developer.getId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "id_token")
                .param(OAuth2Utils.STATE, "random-state")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> tokenResponse = splitQuery(url);
        assertNotNull(tokenResponse.get(OAuth2Utils.STATE));
        assertNotNull(tokenResponse.get("id_token"));
        assertEquals("random-state", tokenResponse.get(OAuth2Utils.STATE).get(0));
    }

    @Test
    void test_Token_Expiry_Time() throws Exception {
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain, new ArrayList<>(defaultAuthorities));
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, null, null, 60 * 60 * 24 * 3650);

        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        Set<String> allUserScopes = new HashSet<>();
        allUserScopes.addAll(defaultAuthorities);
        allUserScopes.addAll(StringUtils.commaDelimitedListToSet(userScopes));

        String token = validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "",
                new ArrayList<>(allUserScopes)
        );

        if (token.length() <= 36) {
            token = webApplicationContext.getBean(JdbcRevocableTokenProvisioning.class).retrieve(token, IdentityZoneHolder.get().getId()).getValue();
        }

        Jwt tokenJwt = JwtHelper.decode(token);

        Map<String, Object> claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        Integer expirationTime = (Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS);

        Calendar nineYearsAhead = new GregorianCalendar();
        nineYearsAhead.setTimeInMillis(System.currentTimeMillis());
        nineYearsAhead.add(Calendar.YEAR, 9);
        assertTrue("Expiration Date should be more than 9 years ahead.", new Date(expirationTime * 1000L).after(new Date(nineYearsAhead.getTimeInMillis())));
    }

    @Test
    void required_user_groups_password_grant() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "*.*";
        Map<String, Object> additional = new HashMap();
        additional.put(ClientConstants.REQUIRED_USER_GROUPS, Collections.singletonList("non.existent"));
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, null, null, -1, null, additional);
        String userId = "testuser" + generator.generate();
        String userScopes = "scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", clientId)
                        .param("client_secret", SECRET)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", developer.getUserName())
                        .param("password", SECRET)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"))
                .andExpect(jsonPath("$.error_description").value("User does not meet the client's required group criteria."))
                .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE));
    }

    @Test
    void testWildcardPasswordGrant() throws Exception {
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain, new ArrayList<>(defaultAuthorities));
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        Set<String> allUserScopes = new HashSet<>();
        allUserScopes.addAll(defaultAuthorities);
        allUserScopes.addAll(StringUtils.commaDelimitedListToSet(userScopes));

        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "",
                new ArrayList<>(allUserScopes)
        );
        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "space.*.developer",
                Arrays.asList("space.1.developer", "space.2.developer")
        );
        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "space.2.developer",
                Collections.singletonList("space.2.developer")
        );
        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "org.123*.admin",
                Collections.singletonList("org.12345.admin")
        );
        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "org.123*.admin,space.1.developer",
                Arrays.asList("org.12345.admin", "space.1.developer")
        );
        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "org.123*.admin,space.*.developer",
                Arrays.asList("org.12345.admin", "space.1.developer", "space.2.developer")
        );
        Set<String> set1 = new HashSet<>(defaultAuthorities);
        set1.addAll(Arrays.asList("org.12345.admin",
                "space.1.developer",
                "space.2.developer",
                "scope.one",
                "scope.two",
                "scope.three"));

        set1.remove("openid");
        set1.remove("profile");
        set1.remove("roles");
        set1.remove(ClaimConstants.USER_ATTRIBUTES);
        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "org.123*.admin,space.*.developer,*.*",
                new ArrayList<>(set1)
        );
        validatePasswordGrantToken(
                clientId,
                userId,
                subdomain,
                "org.123*.admin,space.*.developer,scope.*",
                Arrays.asList("org.12345.admin", "space.1.developer", "space.2.developer", "scope.one", "scope.two", "scope.three")
        );


    }

    @Test
    void testLoginAddNewUserForOauthTokenPasswordGrant() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");
        //the login server is matched by providing
        //1. Bearer token (will be authenticated for oauth.login scope)
        //2. source=login
        //3. grant_type=password
        //4. add_new=<any value>
        //without the above four parameters, it is not considered a external login-server request
        String username = generator.generate();
        String email = username + "@addnew.test.org";
        String first = "firstName";
        String last = "lastName";
        //success - contains everything we need
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "true")
                .param("grant_type", "password")
                .param("client_id", "cf")
                .param("client_secret", "")
                .param("username", username)
                .param("family_name", last)
                .param("given_name", first)
                .param("email", email))
                .andExpect(status().isOk());
        UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
        UaaUser user = db.retrieveUserByName(username, OriginKeys.LOGIN_SERVER);
        assertNotNull(user);
        assertEquals(username, user.getUsername());
        assertEquals(email, user.getEmail());
        assertEquals(first, user.getGivenName());
        assertEquals(last, user.getFamilyName());
    }

    @Test
    void testLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.LOGIN_SERVER, IdentityZoneHolder.get().getId());
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");
        String basicAuthForLoginClient = new String(Base64.encode(String.format("%s:%s", "login", "loginsecret").getBytes()));

        //the login server is matched by providing
        //1. Bearer token (will be authenticated for oauth.login scope)
        //2. source=login
        //3. grant_type=password
        //4. add_new=<any value>
        //without the above four parameters, it is not considered a external login-server request

        //success - contains everything we need
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isOk());

        //success - user_id only, contains everything we need
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("user_id", developer.getId()))
                .andExpect(status().isOk());

        //success - username/origin only, contains everything we need
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isOk());

        //failure - missing client ID
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_secret", SECRET)
                .param("user_id", developer.getId()))
                .andExpect(status().isUnauthorized());

        //failure - invalid client ID
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", "dasdasdadas")
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isUnauthorized());

        //failure - invalid client secret
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET + "dasdasasas")
                .param("user_id", developer.getId()))
                .andExpect(status().isUnauthorized());

        //failure - missing client_id and secret
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isUnauthorized());

        //failure - invalid user ID - user_id takes priority over username/origin so it must fail
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId() + "1dsda")
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isUnauthorized());

        //failure - no user ID and an invalid origin must fail
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param(OriginKeys.ORIGIN, developer.getOrigin() + "dasda"))
                .andExpect(status().isUnauthorized());

        //failure - no user ID, invalid username must fail
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName() + "asdasdas")
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isUnauthorized());


        //success - pretend to be login server - add new user is true - any username will be added
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "true")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName() + "AddNew" + (generator.generate()))
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isOk());

        //failure - pretend to be login server - add new user is false
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName() + "AddNew" + (generator.generate()))
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isUnauthorized());

        //failure - source=login missing, so missing user password should trigger a failure
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + basicAuthForLoginClient)
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isUnauthorized());

        //failure - add_new is missing, so missing user password should trigger a failure
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + basicAuthForLoginClient)
                .param("source", "login")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testOtherOauthResourceLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);


        String oauthClientId = "testclient" + generator.generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES, true);


        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(oauthClientId, SECRET, "");

        //failure - success only if token has oauth.login
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());

        //failure - success only if token has oauth.login
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("user_id", developer.getId()))
                .andExpect(status().isForbidden());

        //failure - success only if token has oauth.login
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());

        //failure - missing client ID
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_secret", SECRET)
                .param("user_id", developer.getId()))
                .andExpect(status().isForbidden());

        //failure - invalid client ID
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", "dasdasdadas")
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());

        //failure - invalid client secret
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET + "dasdasasas")
                .param("user_id", developer.getId()))
                .andExpect(status().isForbidden());

        //failure - missing client_id and secret
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("username", developer.getUserName())
                .param("user_id", developer.getId())
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());

        //failure - invalid user ID - user_id takes priority over username/origin so it must fail
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("user_id", developer.getId() + "1dsda")
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());

        //failure - no user ID and an invalid origin must fail
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param(OriginKeys.ORIGIN, developer.getOrigin() + "dasda"))
                .andExpect(status().isForbidden());

        //failure - no user ID, invalid username must fail
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName() + "asdasdas")
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());


        //failure - success only if token has oauth.login
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "true")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName() + "AddNew" + (generator.generate()))
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());

        //failure - pretend to be login server - add new user is false
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + loginToken)
                .param("source", "login")
                .param("add_new", "false")
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName() + "AddNew" + (generator.generate()))
                .param(OriginKeys.ORIGIN, developer.getOrigin()))
                .andExpect(status().isForbidden());
    }

    @Test
    void testOtherClientAuthenticationMethods() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String oauthClientId = "testclient" + generator.generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something,uaa.user";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES, true);


        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,uaa.user";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String basicAuthForOauthClient = new String(Base64.encode(String.format("%s:%s", oauthClientId, SECRET).getBytes()));

        //success - regular password grant but client is authenticated using POST parameters
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_FORM_URLENCODED)
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("password", SECRET))
                .andExpect(status().is2xxSuccessful());

        //success - regular password grant but client is authenticated using token
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + basicAuthForOauthClient)
                .header("Content-Type", APPLICATION_FORM_URLENCODED)
                .param("grant_type", "password")
                .param("client_id", oauthClientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("password", SECRET))
                .andExpect(status().is2xxSuccessful());

        //failure - client ID mismatch with client authenticated using POST parameters
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + basicAuthForOauthClient)
                .header("Content-Type", APPLICATION_FORM_URLENCODED)
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", developer.getUserName())
                .param("password", SECRET))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGetClientCredentialsTokenForDefaultIdentityZone() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        assertNotNull(bodyMap.get("access_token"));
        Jwt jwt = JwtHelper.decode((String) bodyMap.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        assertNotNull(claims.get(ClaimConstants.AUTHORITIES));
        assertNotNull(claims.get(ClaimConstants.AZP));
        assertNull(claims.get(ClaimConstants.USER_ID));
    }

    @Test
    void clientCredentials_byDefault_willNotLockoutClientsUsingFormData() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        for (int i = 0; i < 6; i++) {
            tryLoginWithWrongSecretInBody(clientId);
        }

        mockMvc
                .perform(post("/oauth/token")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "client_credentials")
                        .param("client_id", clientId)
                        .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    @Test
    void clientCredentials_byDefault_WillNotLockoutDuringUnsuccessfulBasicAuth() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        for (int i = 0; i < 6; i++) {
            tryLoginWithWrongSecretInHeader(clientId);
        }

        login(clientId);
    }

    @Test
    void clientCredentials_byDefault_WillNotLockoutDuringUnsuccessfulBasicAuthAndFormData() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        for (int i = 0; i < 3; i++) {
            tryLoginWithWrongSecretInHeader(clientId);
            tryLoginWithWrongSecretInBody(clientId);
        }

        login(clientId);
    }

    @Test
    void validateOldTokenAfterAddClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);

        clientDetailsService.addClientSecret(clientId, "newSecret", IdentityZoneHolder.get().getId());
        mockMvc.perform(post("/check_token")
                .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                .param("token", access_token))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    void validateNewTokenAfterAddClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        clientDetailsService.addClientSecret(clientId, "newSecret", IdentityZoneHolder.get().getId());

        for (String secret : Arrays.asList(SECRET, "newSecret")) {
            String body = mockMvc.perform(post("/oauth/token")
                    .accept(MediaType.APPLICATION_JSON_VALUE)
                    .with(httpBasic(clientId, SECRET))
                    .param("grant_type", "client_credentials")
                    .param("client_id", clientId)
                    .param("client_secret", secret))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
            });
            String access_token = (String) bodyMap.get("access_token");
            assertNotNull(access_token);

            mockMvc.perform(post("/check_token")
                    .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                    .param("token", access_token))
                    .andExpect(status().isOk());
        }
    }

    @Test
    void validateOldTokenAfterDeleteClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);

        clientDetailsService.addClientSecret(clientId, "newSecret", IdentityZoneHolder.get().getId());
        clientDetailsService.deleteClientSecret(clientId, IdentityZoneHolder.get().getId());

        MockHttpServletResponse response = mockMvc.perform(post("/check_token")
                .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                .param("token", access_token))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse();

        InvalidTokenException tokenRevokedException = JsonUtils.readValue(response.getContentAsString(), TokenRevokedException.class);
        assertEquals("invalid_token", tokenRevokedException.getOAuth2ErrorCode());
        assertEquals("revocable signature mismatch", tokenRevokedException.getMessage());
    }

    @Test
    void validateNewTokenBeforeDeleteClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        clientDetailsService.addClientSecret(clientId, "newSecret", IdentityZoneHolder.get().getId());

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);


        clientDetailsService.deleteClientSecret(clientId, IdentityZoneHolder.get().getId());

        mockMvc.perform(post("/check_token")
                .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                .param("token", access_token))
                .andExpect(status().isOk());
    }

    @Test
    void validateNewTokenAfterDeleteClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        clientDetailsService.addClientSecret(clientId, "newSecret", IdentityZoneHolder.get().getId());
        clientDetailsService.deleteClientSecret(clientId, IdentityZoneHolder.get().getId());

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":newSecret").getBytes())))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);

        mockMvc.perform(post("/check_token")
                .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                .param("token", access_token))
                .andExpect(status().isOk());
    }

    @Test
    void testGetClientCredentials_WithAuthoritiesExcluded_ForDefaultIdentityZone() throws Exception {
        Set<String> originalExclude = webApplicationContext.getBean(UaaTokenServices.class).getExcludedClaims();
        try {
            webApplicationContext.getBean(UaaTokenServices.class).setExcludedClaims(new HashSet<>(Arrays.asList(ClaimConstants.AUTHORITIES, ClaimConstants.AZP)));
            String clientId = "testclient" + generator.generate();
            String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
            setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

            String body = mockMvc.perform(post("/oauth/token")
                    .accept(MediaType.APPLICATION_JSON_VALUE)
                    .with(httpBasic(clientId, SECRET))
                    .param("grant_type", "client_credentials")
                    .param("client_id", clientId)
                    .param("client_secret", SECRET))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
            });
            assertNotNull(bodyMap.get("access_token"));
            Jwt jwt = JwtHelper.decode((String) bodyMap.get("access_token"));
            Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
            assertNull(claims.get(ClaimConstants.AUTHORITIES));
            assertNull(claims.get(ClaimConstants.AZP));
        } finally {
            webApplicationContext.getBean(UaaTokenServices.class).setExcludedClaims(originalExclude);
        }
    }

    @Test
    void testGetClientCredentialsTokenForOtherIdentityZone() throws Exception {
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        IdentityZoneHolder.clear();
        mockMvc.perform(post("http://" + subdomain + ".localhost/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk());
    }

    @Test
    void misconfigured_jwt_keys_returns_proper_error() throws Exception {
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        testZone.getConfig().getTokenPolicy().setActiveKeyId("invalid-active-key");
        identityZoneProvisioning.update(testZone);
        IdentityZoneHolder.set(testZone);
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        IdentityZoneHolder.clear();

        mockMvc.perform(post("http://localhost/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Host", subdomain + ".localhost")
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("unauthorized"))
                .andExpect(jsonPath("$.error_description").value("Unable to sign token, misconfigured JWT signing keys"));
    }

    @Test
    void testGetClientCredentialsTokenForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        IdentityZoneHolder.clear();
        mockMvc.perform(post("http://localhost/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                //.header("Host", subdomain + ".localhost") - with updated Spring, this now works for request.getServerName
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGetClientCredentialsTokenForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String subdomain = "testzone" + generator.generate();
        setupIdentityZone(subdomain);
        mockMvc.perform(post("http://" + subdomain + ".localhost/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGetPasswordGrantInvalidPassword() throws Exception {
        String username = generator.generate() + "@test.org";
        IdentityZoneHolder.clear();
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI,
                Collections.singletonList(OriginKeys.UAA));
        setUpUser(username);
        IdentityZoneHolder.clear();
        mockMvc.perform(post("/oauth/token")
                .param("username", username)
                .param("password", "badsecret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("{\"error\":\"unauthorized\",\"error_description\":\"Bad credentials\"}"));
    }

    @Test
    void testGetPasswordGrantTokenExpiredPasswordForOtherZone() throws Exception {
        String username = generator.generate() + "@test.org";
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider<UaaIdentityProviderDefinition> provider = setupIdentityProvider();
        UaaIdentityProviderDefinition config = provider.getConfig();
        if (config == null) {
            config = new UaaIdentityProviderDefinition(null, null);
        }
        PasswordPolicy passwordPolicy = new PasswordPolicy(6, 128, 1, 1, 1, 0, 6);
        config.setPasswordPolicy(passwordPolicy);
        provider.setConfig(config);
        identityProviderProvisioning.update(provider, provider.getIdentityZoneId());
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI,
                Collections.singletonList(provider.getOriginKey()));
        setUpUser(username);
        IdentityZoneHolder.clear();

        mockMvc.perform(post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isOk());

        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(System.currentTimeMillis());
        cal.add(Calendar.YEAR, -1);
        Timestamp t = new Timestamp(cal.getTimeInMillis());
        assertEquals(1, webApplicationContext.getBean(JdbcTemplate.class).update("UPDATE users SET passwd_lastmodified = ? WHERE username = ?", t, username));

        mockMvc.perform(post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("{\"error\":\"unauthorized\",\"error_description\":\"password change required\"}"));
    }

    @Test
    void password_grant_with_default_user_groups_in_zone() throws Exception {
        String username = generator.generate() + "@test.org";
        String subdomain = "testzone" + generator.generate();
        String clientId = "testclient" + generator.generate();
        List<String> defaultGroups = new LinkedList(Arrays.asList("custom.default.group", "other.default.group"));
        defaultGroups.addAll(UserConfig.DEFAULT_ZONE_GROUPS);
        createNonDefaultZone(username, subdomain, clientId, defaultGroups, "custom.default.group,openid");

        MvcResult result = mockMvc.perform(post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isOk())
                .andReturn();
        String claimsJSON = JwtHelper.decode(JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class).accessToken).getClaims();
        Claims claims = JsonUtils.readValue(claimsJSON, Claims.class);
        assertEquals(claims.getIss(), "http://" + subdomain.toLowerCase() + ".localhost:8080/uaa/oauth/token");
        assertThat(claims.getScope(), containsInAnyOrder("openid", "custom.default.group"));
    }

    @Test
    void testGetPasswordGrantTokenForOtherZone() throws Exception {
        String username = generator.generate() + "@test.org";
        String subdomain = "testzone" + generator.generate();
        String clientId = "testclient" + generator.generate();
        createNonDefaultZone(username, subdomain, clientId);

        MvcResult result = mockMvc.perform(post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isOk())
                .andReturn();
        String claimsJSON = JwtHelper.decode(JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class).accessToken).getClaims();
        Claims claims = JsonUtils.readValue(claimsJSON, Claims.class);
        assertEquals(claims.getIss(), "http://" + subdomain.toLowerCase() + ".localhost:8080/uaa/oauth/token");
    }

    @Test
    void testGetPasswordGrantForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
        String username = generator.generate() + "@test.org";
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true);

        setUpUser(username);
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        IdentityZoneHolder.clear();

        mockMvc.perform(post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isUnauthorized());
    }

    @Test
    void testGetPasswordGrantForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
        String username = generator.generate() + "@test.org";
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true);

        setUpUser(username);

        IdentityZoneHolder.clear();

        mockMvc.perform(post("/oauth/token")
                .param("username", username)
                .param("password", "secret")
                .with(httpBasic(clientId, SECRET))
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isUnauthorized());
    }

    @Test
    void testGetTokenScopesNotInAuthentication() throws Exception {
        String subdomain = "testzone" + generator.generate().toLowerCase();
        IdentityZone testZone = setupIdentityZone(subdomain, new ArrayList<>(defaultAuthorities));
        IdentityZoneHolder.set(testZone);

        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "zones.*.admin,openid,cloud_controller.read,cloud_controller.write";
        setUpClients(clientId, "", scopes, "authorization_code,password,refresh_token", true, "http://localhost/test");

        ScimUser user = setUpUser(generator.generate() + "@test.org");

        String zoneAdminGroup = "zones." + generator.generate() + ".admin";
        ScimGroup group = new ScimGroup(null, zoneAdminGroup, IdentityZone.getUaaZoneId());
        group = jdbcScimGroupProvisioning.create(group, IdentityZoneHolder.get().getId());
        ScimGroupMember member = new ScimGroupMember(user.getId());
        jdbcScimGroupMembershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(user);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Host", subdomain + ".localhost")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(location);
        String code = builder.build().getQueryParams().get("code").get(0);

        authRequest = post("/oauth/token")
                .with(httpBasic(clientId, SECRET))
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .header("Host", subdomain + ".localhost")
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        result = mockMvc.perform(authRequest).andDo(print()).andExpect(status().is2xxSuccessful()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);

        IdentityZoneHolder.set(testZone);
        OAuth2Authentication authContext = tokenServices.loadAuthentication(oauthToken.accessToken);

        assertEquals(4, authContext.getOAuth2Request().getScope().size());
        assertThat(
                authContext.getOAuth2Request().getScope(),
                containsInAnyOrder(zoneAdminGroup, "openid", "cloud_controller.read", "cloud_controller.write")
        );
    }

    @Test
    void testGetTokenPromptLogin() throws Exception {

        ScimUser user = setUpUser(generator.generate() + "@test.org");

        String zoneadmingroup = "zones." + generator.generate() + ".admin";
        ScimGroup group = new ScimGroup(null, zoneadmingroup, IdentityZone.getUaaZoneId());
        group = jdbcScimGroupProvisioning.create(group, IdentityZoneHolder.get().getId());
        ScimGroupMember member = new ScimGroupMember(user.getId());
        jdbcScimGroupMembershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(user);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Authorization", "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64(("identity:identitysecret").getBytes())))
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .session(session)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param("prompt", "login")
                .param(OAuth2Utils.CLIENT_ID, "identity")
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        assertEquals(result.getRequest().getRequestURL().toString(), result.getResponse().getRedirectedUrl().split("\\?")[0]);
        Map<String, String[]> mapRequest = result.getRequest().getParameterMap();
        Map<String, String[]> mapResponse = UaaUrlUtils.getParameterMap(result.getResponse().getRedirectedUrl());
        for (String key : mapResponse.keySet()) {
            assertTrue(mapRequest.containsKey(key));
            assertArrayEquals(mapRequest.get(key), mapResponse.get(key));
        }
        Set<String> requestKeys = new HashSet(mapRequest.keySet());
        requestKeys.removeAll(mapResponse.keySet());
        assertEquals(1, requestKeys.size());
        assertTrue(requestKeys.contains("prompt"));
    }

    @Test
    void testGetTokenMaxAge() throws Exception {

        ScimUser user = setUpUser(generator.generate() + "@test.org");

        String zoneadmingroup = "zones." + generator.generate() + ".admin";
        ScimGroup group = new ScimGroup(null, zoneadmingroup, IdentityZone.getUaaZoneId());
        group = jdbcScimGroupProvisioning.create(group, IdentityZoneHolder.get().getId());
        ScimGroupMember member = new ScimGroupMember(user.getId());
        jdbcScimGroupMembershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(user);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Authorization", "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64(("identity:identitysecret").getBytes())))
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .session(session)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param("max_age", "1")
                .param(OAuth2Utils.CLIENT_ID, "identity")
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        assertEquals("http://localhost/test", result.getResponse().getRedirectedUrl().split("\\?")[0]);
        Thread.sleep(2000);

        authRequest = get("/oauth/authorize")
                .header("Authorization", "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64(("identity:identitysecret").getBytes())))
                .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                .session(session)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param("max_age", "1")
                .param(OAuth2Utils.CLIENT_ID, "identity")
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        assertEquals(result.getRequest().getRequestURL().toString(), result.getResponse().getRedirectedUrl().split("\\?")[0]);
        Map<String, String[]> mapRequest = result.getRequest().getParameterMap();
        Map<String, String[]> mapResponse = UaaUrlUtils.getParameterMap(result.getResponse().getRedirectedUrl());
        for (String key : mapResponse.keySet()) {
            assertTrue(mapRequest.containsKey(key));
            assertArrayEquals(mapRequest.get(key), mapResponse.get(key));
        }
        Set<String> requestKeys = new HashSet(mapRequest.keySet());
        requestKeys.removeAll(mapResponse.keySet());
        assertEquals(1, requestKeys.size());
        assertTrue(requestKeys.contains("max_age"));
    }

    @Test
    void testRevocablePasswordGrantTokenForDefaultZone() throws Exception {
        String tokenKey = "access_token";
        Map<String, Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(new HashedMap());
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String) tokenResponse.get(tokenKey);
        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        assertNotNull("Token revocation signature must exist", claims.get(ClaimConstants.REVOCATION_SIGNATURE));
        assertTrue("Token revocation signature must be a string", claims.get(ClaimConstants.REVOCATION_SIGNATURE) instanceof String);
        assertTrue("Token revocation signature must have data", StringUtils.hasText((String) claims.get(ClaimConstants.REVOCATION_SIGNATURE)));
    }

    @Test
    void testPasswordGrantTokenForDefaultZone_Opaque() throws Exception {
        Map<String, String> parameters = new HashedMap();
        parameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        String tokenKey = "access_token";
        Map<String, Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(parameters);
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String) tokenResponse.get(tokenKey);
        assertThat("Token must be shorter than 37 characters", token.length(), lessThanOrEqualTo(36));

        RevocableToken revocableToken = webApplicationContext.getBean(RevocableTokenProvisioning.class).retrieve(token, IdentityZoneHolder.get().getId());
        assertNotNull("Token should have been stored in the DB", revocableToken);

        Jwt jwt = JwtHelper.decode(revocableToken.getValue());
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        assertNotNull("Revocable claim must exist", claims.get(ClaimConstants.REVOCABLE));
        assertTrue("Token revocable claim must be set to true", (Boolean) claims.get(ClaimConstants.REVOCABLE));
    }

    @Test
    void testNonDefaultZone_Jwt_Revocable() throws Exception {
        String username = generator.generate() + "@test.org";
        String subdomain = "testzone" + generator.generate();
        String clientId = "testclient" + generator.generate();

        createNonDefaultZone(username, subdomain, clientId);
        IdentityZoneProvisioning zoneProvisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        IdentityZone defaultZone = zoneProvisioning.retrieveBySubdomain(subdomain);
        try {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
            zoneProvisioning.update(defaultZone);
            MockHttpServletRequestBuilder post = post("/oauth/token")
                    .with(httpBasic(clientId, SECRET))
                    .header("Host", subdomain + ".localhost")
                    .param("username", username)
                    .param("password", "secret")
                    .param(OAuth2Utils.GRANT_TYPE, "password")
                    .param(OAuth2Utils.CLIENT_ID, clientId);
            Map<String, Object> tokenResponse = JsonUtils.readValue(
                    mockMvc.perform(post)
                            .andDo(print())
                            .andExpect(status().isOk())
                            .andReturn().getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {
                    });
            validateRevocableJwtToken(tokenResponse, defaultZone);
        } finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            zoneProvisioning.update(defaultZone);
        }
    }

    @Test
    void testDefaultZone_Jwt_Revocable() throws Exception {
        IdentityZoneProvisioning zoneProvisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        IdentityZone defaultZone = zoneProvisioning.retrieve(IdentityZone.getUaaZoneId());
        try {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
            zoneProvisioning.update(defaultZone);
            Map<String, String> parameters = new HashedMap();
            Map<String, Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(parameters);
            validateRevocableJwtToken(tokenResponse, defaultZone);
        } finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            zoneProvisioning.update(defaultZone);
        }
    }

    @Test
    void testRefreshGrantWithAccessToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", "marissa")
                .param("password", "koala"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        String accessToken = (String) bodyMap.get("access_token");
        assertNotNull(accessToken);

        doRefreshGrant(accessToken, clientId, SECRET, status().isUnauthorized());
    }

    @Test
    void testRefreshGrant_returnsValidAccessToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param("username", "marissa")
                .param("password", "koala"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
        String refreshToken = (String) bodyMap.get("refresh_token");

        assertNotNull(refreshToken);

        body = doRefreshGrant(refreshToken, clientId, SECRET, status().isOk()).getResponse().getContentAsString();
        CompositeToken tokenResponse = JsonUtils.readValue(body, CompositeToken.class);
        Map<String, Object> claims = UaaTokenUtils.getClaims(tokenResponse.getValue());

        assertThat(claims.get(JTI).toString(), not(endsWith("-r")));
    }

    @Test
    void testJkuHeaderIsSet_andNonRfcHeadersNotSet_forAccessToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param(CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", "marissa")
                .param("password", "koala")
        ).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        CompositeToken tokenResponse = JsonUtils.readValue(body, CompositeToken.class);
        String accessTokenHeaderRaw = tokenResponse.getValue().split("\\.")[0];
        String accessTokenHeaderJson = new String(java.util.Base64.getDecoder().decode(accessTokenHeaderRaw));
        Map<String, Object> headerMap =
                JsonUtils.readValue(accessTokenHeaderJson, new TypeReference<Map<String, Object>>() {
                });

        assertThat(headerMap.get("jku"), is("https://localhost:8080/uaa/token_keys"));
        // `enc` and `iv` are not required by JWT or OAuth spec, so should not be set and thus not returned in the token's header
        assertThat(headerMap, not(hasKey("enc")));
        assertThat(headerMap, not(hasKey("iv")));
    }

    @Test
    void testJkuHeaderIsSet_andNonRfcHeadersNotSet_forRefreshToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param(CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", "marissa")
                .param("password", "koala")
        ).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        CompositeToken tokenResponse = JsonUtils.readValue(body, CompositeToken.class);
        assertThat(tokenResponse.getRefreshToken(), is(notNullValue()));

        String refreshTokenHeaderRaw = tokenResponse.getRefreshToken().getValue().split("\\.")[0];
        String refreshTokenHeaderJson = new String(java.util.Base64.getDecoder().decode(refreshTokenHeaderRaw));
        Map<String, Object> headerMap =
                JsonUtils.readValue(refreshTokenHeaderJson, new TypeReference<Map<String, Object>>() {
                });

        assertThat(headerMap.get("jku"), is("https://localhost:8080/uaa/token_keys"));
        // `enc` and `iv` are not required by JWT or OAuth spec, so should not be set and thus not returned in the token's header
        assertThat(headerMap, not(hasKey("enc")));
        assertThat(headerMap, not(hasKey("iv")));
    }

    @Test
    void testJkuHeaderIsSet_andNonRfcHeadersNotSet_forIdToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user,openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param(CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", "marissa")
                .param("password", "koala")
                .param("response_type", "id_token")
        ).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        CompositeToken tokenResponse = JsonUtils.readValue(body, CompositeToken.class);
        assertThat(tokenResponse.getIdTokenValue(), is(notNullValue()));

        String idTokenHeaderRaw = tokenResponse.getIdTokenValue().split("\\.")[0];
        String idTokenHeaderJson = new String(java.util.Base64.getDecoder().decode(idTokenHeaderRaw));
        Map<String, Object> headerMap =
                JsonUtils.readValue(idTokenHeaderJson, new TypeReference<Map<String, Object>>() {
                });

        assertThat(headerMap.get("jku"), is("https://localhost:8080/uaa/token_keys"));
        // `enc` and `iv` are not required by JWT or OAuth spec, so should not be set and thus not returned in the token's header
        assertThat(headerMap, not(hasKey("enc")));
        assertThat(headerMap, not(hasKey("iv")));
    }

    @Test
    void authorizationCanRedirectToSubpathOfConfiguredRedirect() throws Exception {
        String clientId = "testclient" + generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Collections.singletonList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI + "/subpath"))
                .andExpect(status().isFound())
                .andReturn();

        String url = result.getResponse().getHeader("Location");
        assertThat(url, containsString(TEST_REDIRECT_URI + "/subpath"));
    }

    private String validatePasswordGrantToken(String clientId, String username, String requestedScopes, List<String> expectedScopes) throws Exception {
        return validatePasswordGrantToken(clientId, username, null, requestedScopes, expectedScopes);
    }

    private String validatePasswordGrantToken(String clientId, String username, String zoneSubdomain, String requestedScopes, List<String> expectedScopes) throws Exception {
        String pwdToken;
        if (zoneSubdomain == null) {
            pwdToken = testClient.getUserOAuthAccessToken(clientId, SECRET, username, SECRET, requestedScopes);
        } else {
            pwdToken = testClient.getUserOAuthAccessTokenForZone(clientId, SECRET, username, SECRET, requestedScopes, zoneSubdomain);
            IdentityZoneHolder.set(identityZoneProvisioning.retrieveBySubdomain(zoneSubdomain));
        }

        OAuth2Authentication authContext = tokenServices.loadAuthentication(pwdToken);

        Set<String> grantedScopes = authContext.getOAuth2Request().getScope();
        assertEquals(expectedScopes.size(), grantedScopes.size());
        assertEquals(grantedScopes, new HashSet<>(expectedScopes));
        IdentityZoneHolder.clear();

        return pwdToken;
    }

    private MockHttpSession getAuthenticatedSession(ScimUser user) {
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, user);
        return session;
    }

    private void test_invalid_registered_redirect_uris(Set<String> redirectUris, ResultMatcher resultMatcher) throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";
        String clientId = "authclient-" + generator.generate();
        String scopes = "openid";
        BaseClientDetails client = setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        client.setRegisteredRedirectUri(redirectUris);
        webApplicationContext.getBean(MultitenantClientServices.class).updateClientDetails(client);

        String username = "authuser" + generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        MockHttpSession session = getAuthenticatedSession(developer);


        String state = generator.generate();

        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .with(httpBasic(clientId, SECRET))
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        mockMvc.perform(authRequest).andExpect(resultMatcher);
    }

    private void validateOpenIdConnectToken(String token, String userId, String clientId) {
        Map<String, Object> result = getClaimsForToken(token);
        TokenEndpointBuilder tokenEndpointBuilder = (TokenEndpointBuilder) webApplicationContext.getBean("tokenEndpointBuilder");
        String iss = (String) result.get(ClaimConstants.ISS);
        assertEquals(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()), iss);
        String sub = (String) result.get(ClaimConstants.SUB);
        assertEquals(userId, sub);
        List<String> aud = (List<String>) result.get(ClaimConstants.AUD);
        assertTrue(aud.contains(clientId));
        Integer exp = (Integer) result.get(ClaimConstants.EXPIRY_IN_SECONDS);
        assertNotNull(exp);
        Integer iat = (Integer) result.get(ClaimConstants.IAT);
        assertNotNull(iat);
        assertTrue(exp > iat);
        List<String> openid = (List<String>) result.get(ClaimConstants.SCOPE);
        assertThat(openid, containsInAnyOrder("openid"));

        Integer auth_time = (Integer) result.get(ClaimConstants.AUTH_TIME);
        assertNotNull(auth_time);
        Long previous_logon_time = (Long) result.get(ClaimConstants.PREVIOUS_LOGON_TIME);
        assertNotNull(previous_logon_time);
        Long dbPreviousLogonTime = webApplicationContext.getBean(UaaUserDatabase.class).retrieveUserById(userId).getPreviousLogonTime();
        assertEquals(dbPreviousLogonTime, previous_logon_time);

    }

    private static Map<String, List<String>> splitQuery(URL url) {
        Map<String, List<String>> params = new LinkedHashMap<>();
        String[] kv = url.getQuery().split("&");
        for (String pair : kv) {
            int i = pair.indexOf("=");
            String key = i > 0 ? URLDecoder.decode(pair.substring(0, i), StandardCharsets.UTF_8) : pair;
            if (!params.containsKey(key)) {
                params.put(key, new LinkedList<String>());
            }
            String value = i > 0 && pair.length() > i + 1 ? URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8) : null;
            params.get(key).add(value);
        }
        return params;
    }

    private MvcResult doPasswordGrant(String username,
                                      String password,
                                      String clientId,
                                      String clientSecret,
                                      ResultMatcher resultMatcher) throws Exception {
        return mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", clientId)
                        .param("client_secret", clientSecret)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", password)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(resultMatcher)
                .andReturn();
    }

    private MvcResult doRefreshGrant(String refreshToken,
                                     String clientId,
                                     String clientSecret,
                                     ResultMatcher resultMatcher) throws Exception {
        return mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", clientId)
                        .param("client_secret", clientSecret)
                        .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                        .param("refresh_token", refreshToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(resultMatcher)
                .andReturn();
    }

    private void performAuthorize(String state, String clientId, String basicDigestHeaderValue, MockHttpSession session, String requestedUri, ResultMatcher status) throws Exception {
        mockMvc.perform(
                get("/oauth/authorize")
                        .header("Authorization", basicDigestHeaderValue)
                        .session(session)
                        .param(OAuth2Utils.RESPONSE_TYPE, "token")
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, requestedUri)
        ).andExpect(status);
    }

    private void testImplicitGrantRedirectUri(String redirectUri, boolean noPrompt) throws Exception {
        String clientId = "authclient-" + generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser" + generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        if (noPrompt) {
            authRequest = authRequest.param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE);
        }

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");

        containsExactlyOneInstance(location, "#");
        String[] locationParts = location.split("#");

        String locationUri = locationParts[0];
        String locationToken = locationParts[1];

        assertEquals(redirectUri.split("#")[0], locationUri);
        String[] locationParams = locationToken.split("&");
        assertThat(Arrays.asList(locationParams), hasItem(is("token_type=bearer")));
        assertThat(Arrays.asList(locationParams), hasItem(startsWith("access_token=")));
    }

    private static void containsExactlyOneInstance(String string, String substring) {
        assertTrue(string.contains(substring));
        assertEquals(string.indexOf(substring), string.lastIndexOf(substring));
    }

    private void logUserInTwice(String userId) {
        // We need to do this so that last logon time and previous logon time are populated on the user
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(userId);
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(userId);
    }

    private void tryLoginWithWrongSecretInHeader(String clientId) throws Exception {
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, BADSECRET))
                .param("grant_type", "client_credentials")
        )
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
    }

    private void tryLoginWithWrongSecretInBody(String clientId) throws Exception {
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", BADSECRET)
        )
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
    }

    private void login(String clientId) throws Exception {
        mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param("grant_type", "client_credentials")
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private void setAuthentication(MockHttpSession session, ScimUser developer) {
        setAuthentication(session, developer, false, "pwd");
    }

    private void setAuthentication(MockHttpSession session, ScimUser developer, boolean forcePasswordChange, String... authMethods) {
        UaaPrincipal p = new UaaPrincipal(developer.getId(), developer.getUserName(), developer.getPrimaryEmail(), OriginKeys.UAA, "", IdentityZoneHolder.get().getId());
        UaaAuthentication auth = new UaaAuthentication(p, UaaAuthority.USER_AUTHORITIES, new UaaAuthenticationDetails(false, "clientId", OriginKeys.ORIGIN, "sessionId"));
        SessionUtils.setPasswordChangeRequired(session, forcePasswordChange);
        auth.setAuthenticationMethods(new HashSet<>(Arrays.asList(authMethods)));
        assertTrue(auth.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(auth);
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockSecurityContext(auth)
        );
    }

    private void createNonDefaultZone(String username, String subdomain, String clientId) {
        createNonDefaultZone(username, subdomain, clientId, UserConfig.DEFAULT_ZONE_GROUPS, "cloud_controller.read");
    }

    private void createNonDefaultZone(String username, String subdomain, String clientId, List<String> defaultUserGroups, String scopes) {
        IdentityZone testZone = setupIdentityZone(subdomain, defaultUserGroups);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider();
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI,
                Collections.singletonList(provider.getOriginKey()));
        setUpUser(username);
        IdentityZoneHolder.clear();
    }

    private ResultActions try_token_with_non_post(MockHttpServletRequestBuilder builder, ResultMatcher status, String expectedContentType) throws Exception {
        String username = createUserForPasswordGrant(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator);

        return mockMvc.perform(
                builder
                        .param("client_id", "cf")
                        .param("client_secret", "")
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andDo(print())
                .andExpect(status)
                .andExpect(header().string(CONTENT_TYPE, expectedContentType));
    }

    private void validateRevocableJwtToken(Map<String, Object> tokenResponse, IdentityZone zone) {
        String tokenKey = "access_token";
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String) tokenResponse.get(tokenKey);
        assertThat("Token must be longer than 36 characters", token.length(), greaterThan(36));

        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        assertNotNull("JTI Claim should be present", claims.get(JTI));
        String tokenId = (String) claims.get(JTI);

        IdentityZoneHolder.set(zone);
        RevocableToken revocableToken = webApplicationContext.getBean(RevocableTokenProvisioning.class).retrieve(tokenId, IdentityZoneHolder.get().getId());
        IdentityZoneHolder.clear();
        assertNotNull("Token should have been stored in the DB", revocableToken);


        jwt = JwtHelper.decode(revocableToken.getValue());
        claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        assertNotNull("Revocable claim must exist", claims.get(ClaimConstants.REVOCABLE));
        assertTrue("Token revocable claim must be set to true", (Boolean) claims.get(ClaimConstants.REVOCABLE));

        assertEquals(token, revocableToken.getValue());
    }

    private Map<String, Object> testRevocablePasswordGrantTokenForDefaultZone(Map<String, String> parameters) throws Exception {
        String username = generator.generate() + "@test.org";
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI,
                Collections.singletonList(OriginKeys.UAA));
        setUpUser(username);

        MockHttpServletRequestBuilder post = post("/oauth/token")
                .with(httpBasic(clientId, SECRET))
                .param("username", username)
                .param("password", "secret")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId);
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            post.param(entry.getKey(), entry.getValue());
        }
        return JsonUtils.readValue(
                mockMvc.perform(post)
                        .andDo(print())
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {
                });

    }

    private ScimUser setUpUser(String username) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(username);
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setOrigin(OriginKeys.UAA);
        return jdbcScimUserProvisioning.createUser(scimUser, "secret", IdentityZoneHolder.get().getId());
    }

    public static class MockSecurityContext implements SecurityContext {

        private static final long serialVersionUID = -1386535243513362694L;

        private Authentication authentication;

        MockSecurityContext(Authentication authentication) {
            this.authentication = authentication;
        }

        @Override
        public Authentication getAuthentication() {
            return this.authentication;
        }

        @Override
        public void setAuthentication(Authentication authentication) {
            this.authentication = authentication;
        }
    }

    Map<String, Object> unmodifiableMap(AuthorizationRequest authorizationRequest) {
        Map<String, Object> authorizationRequestMap = new HashMap<>();

        authorizationRequestMap.put(OAuth2Utils.CLIENT_ID, authorizationRequest.getClientId());
        authorizationRequestMap.put(OAuth2Utils.STATE, authorizationRequest.getState());
        authorizationRequestMap.put(OAuth2Utils.REDIRECT_URI, authorizationRequest.getRedirectUri());

        if (authorizationRequest.getResponseTypes() != null) {
            authorizationRequestMap.put(OAuth2Utils.RESPONSE_TYPE,
                    Set.copyOf(authorizationRequest.getResponseTypes()));
        }
        if (authorizationRequest.getScope() != null) {
            authorizationRequestMap.put(OAuth2Utils.SCOPE,
                    Set.copyOf(authorizationRequest.getScope()));
        }

        authorizationRequestMap.put("approved", authorizationRequest.isApproved());

        if (authorizationRequest.getResourceIds() != null) {
            authorizationRequestMap.put("resourceIds",
                    Set.copyOf(authorizationRequest.getResourceIds()));
        }
        if (authorizationRequest.getAuthorities() != null) {
            authorizationRequestMap.put("authorities",
                    Set.<GrantedAuthority>copyOf(authorizationRequest.getAuthorities()));
        }

        return authorizationRequestMap;
    }
}
