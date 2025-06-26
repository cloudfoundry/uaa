package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.collections4.map.HashedMap;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.OAuthToken;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenRevokedException;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
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
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Base64;
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

import java.io.Serial;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.JwtTokenUtils.getClaimsForToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setDisableInternalAuth;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REFRESH_TOKEN_SUFFIX;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
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

@TestPropertySource(properties = {"uaa.url=https://localhost:8080/uaa", "jwt.token.refresh.format=jwt"})
// public for LimitedModeTokenMockMvcTests
public class TokenMvcMockTests extends AbstractTokenMockMvcTests {
    private static final String BAD_SECRET = "badsecret";
    protected AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();

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
        try_token_with_non_post(get("/oauth/token"), status().isOk(), APPLICATION_JSON_VALUE);
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {
            "jwt.token.queryString.enabled=false"
    })
    class WithDisallowedQueryString {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private JdbcScimUserProvisioning jdbcScimUserProvisioning;
        @Autowired
        private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;
        @Autowired
        private JdbcScimGroupProvisioning jdbcScimGroupProvisioning;

        private String username;

        @BeforeEach
        void setUp() {
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
                    .andExpect(jsonPath("$.error_description").value("Request method 'GET' is not supported"));
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
                .andExpect(jsonPath("$.error_description").value("Request method 'PUT' is not supported"));

    }

    @Test
    void token_endpoint_delete() throws Exception {
        try_token_with_non_post(delete("/oauth/token"), status().isMethodNotAllowed(), APPLICATION_JSON_VALUE)
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'DELETE' is not supported"));

    }

    @Test
    void token_endpoint_post() throws Exception {
        try_token_with_non_post(post("/oauth/token"), status().isOk(), APPLICATION_JSON_VALUE);
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
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", "password,refresh_token", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetailsService.addClientDetails(clientDetails);
        MvcResult result = doPasswordGrant(username, SECRET, clientId, SECRET, status().isOk());

        Map<String, Object> tokenResponse = JsonUtils.readValue(
                result.getResponse().getContentAsString(),
                new TypeReference<>() {
                }
        );

        String refreshToken = (String) tokenResponse.get(REFRESH_TOKEN);
        assertThat(refreshToken).isNotNull();

        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Collections.singletonList("uaa.admin"));
        clientDetailsService.updateClientDetails(clientDetails);

        result = doRefreshGrant(refreshToken, clientId, SECRET, status().isUnauthorized());
        assertThat(result.getResponse().getContentAsString()).contains("User does not meet the client's required group criteria.");
    }

    @Test
    void authorization_code_missing_required_scopes() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource", "http://localhost");
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
        assertThat(location).contains("http://localhost");
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUri(new URI(location)).build().getQueryParams();
        assertThat(queryParams).isNotNull();
        assertThat(queryParams.getFirst("error")).isNotNull();
        assertThat(queryParams.getFirst("error_description")).isNotNull()
                .contains(UriUtils.encodeQueryParam("User does not meet the client's required group criteria.", "ISO-8859-1"));
    }

    @Test
    void authorization_code_missing_required_scopes_during_token_fetch() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource", "http://localhost");
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
        assertThat(location).contains("http://localhost");
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUri(new URI(location)).build().getQueryParams();
        assertThat(queryParams).isNotNull();
        String code = queryParams.getFirst("code");
        assertThat(code).isNotNull();

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
                new TypeReference<>() {
                }
        );

        assertThat((String) errorResponse.get("error_description")).contains("User does not meet the client's required group criteria.");
    }

    @Test
    void token_grant_missing_required_groups() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", "password", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Collections.singletonList("uaa.admin"));
        clientDetailsService.addClientDetails(clientDetails);
        MvcResult result = doPasswordGrant(username, SECRET, clientId, SECRET, status().isBadRequest());
        Map<String, Object> errorResponse = JsonUtils.readValue(
                result.getResponse().getContentAsString(),
                new TypeReference<>() {
                }
        );

        assertThat((String) errorResponse.get("error_description")).contains("User does not meet the client's required group criteria.");
    }

    @Test
    void token_grant_required_groups_are_present() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,required.scope.1,required.scope.2";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope,required.scope.1,required.scope.2", "password", "uaa.resource", null);
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
        assertThat(webApplicationContext.getBean(JdbcTemplate.class).update("UPDATE users SET passwd_change_required = ? WHERE ID = ?", true, user.getId())).isOne();
        doPasswordGrant(username, SECRET, "cf", "", status().is4xxClientError());
    }

    @Test
    void logon_timestamps_with_password_grant() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        ScimUserProvisioning provisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        ScimUser scimUser = provisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
        assertThat(scimUser.getLastLogonTime()).isNull();
        assertThat(scimUser.getPreviousLogonTime()).isNull();

        doPasswordGrant(username, SECRET, "cf", "", status().isOk());
        scimUser = provisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
        assertThat(scimUser.getLastLogonTime()).isNotNull();
        assertThat(scimUser.getPreviousLogonTime()).isNull();

        long lastLogonTime = scimUser.getLastLogonTime();
        doPasswordGrant(username, SECRET, "cf", "", status().isOk());
        scimUser = provisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId());
        assertThat(scimUser.getLastLogonTime()).isNotNull();
        assertThat(scimUser.getPreviousLogonTime()).isNotNull();
        assertThat((long) scimUser.getPreviousLogonTime()).isEqualTo(lastLogonTime);
        assertThat(scimUser.getLastLogonTime()).isGreaterThan(scimUser.getPreviousLogonTime());

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
                                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                                .param("username", username)
                                .param("password", SECRET)
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        Map<String, String> error = JsonUtils.readValue(response, new TypeReference<>() {
        });
        String errorDescription = error.get("error_description");
        assertThat(errorDescription).isNotNull()
                .isEqualTo("password change required");

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

        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<>() {
        });
        Object accessToken = tokens.get(ACCESS_TOKEN);
        Object jti = tokens.get(JTI);
        assertThat(accessToken).isNotNull();
        assertThat(jti).isNotNull();
    }

    @Test
    void encoded_char_on_authorize_url() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        mockMvc.perform(
                        get("/oauth/authorize")
                                .param("client_id", String.valueOf('\u0000'))
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
        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<>() {
        });
        String scopes = (String) tokens.get(SCOPE);
        assertThat(scopes).contains("uaa.admin");
        Object refreshToken = tokens.get(REFRESH_TOKEN);
        String refreshTokenId = (String) refreshToken;

        List<ScimGroup> groups = webApplicationContext.getBean(ScimGroupProvisioning.class).query("displayName eq \"uaa.admin\"", IdentityZoneHolder.get().getId());
        assertThat(groups).hasSize(1);
        webApplicationContext.getBean(ScimGroupMembershipManager.class).removeMemberById(groups.getFirst().getId(), scimUser.getId(), IdentityZoneHolder.get().getId());

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
    void token_ids() throws Exception {
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
        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<>() {
        });
        Object accessToken = tokens.get(ACCESS_TOKEN);
        Object refreshToken = tokens.get(REFRESH_TOKEN);
        Object jti = tokens.get(JTI);
        assertThat(accessToken).isNotNull();
        assertThat(refreshToken).isNotNull();
        assertThat(jti).isNotNull();
        assertThat(accessToken).isEqualTo(jti);
        assertThat(refreshToken).isNotEqualTo(accessToken + REFRESH_TOKEN_SUFFIX);
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
        tokens = JsonUtils.readValue(response, new TypeReference<>() {
        });
        accessToken = tokens.get(ACCESS_TOKEN);
        refreshToken = tokens.get(REFRESH_TOKEN);
        jti = tokens.get(JTI);
        assertThat(accessToken).isNotNull();
        assertThat(refreshToken).isNotNull();
        assertThat(jti).isNotNull();
        assertThat(accessToken).isEqualTo(jti);
        assertThat(refreshToken).isNotEqualTo(accessToken + REFRESH_TOKEN_SUFFIX);
        assertThat(accessTokenId).isNotEqualTo(accessToken);
        assertThat(jti)
                .isEqualTo(accessToken)
                .isNotEqualTo(refreshToken);
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
        String code = ((List<String>) query.get("code")).getFirst();
        assertThat(code).hasSizeGreaterThan(9);

        state = ((List<String>) query.get("state")).getFirst();
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
        String code = ((List<String>) query.get("code")).getFirst();

        assertThat(code).hasSizeGreaterThan(9);

        state = ((List<String>) query.get("state")).getFirst();

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
    void refreshTokenNotPresentWhenClientDoesNotHaveGrantType() throws Exception {
        UaaClientDetails clientWithoutRefreshTokenGrant = setUpClients("testclient" + generator.generate(), "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, true);
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        MockHttpSession session = getAuthenticatedSession(developer);

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                        .session(session)
                        .param(RESPONSE_TYPE, "code")
                        .param(OAuth2Utils.CLIENT_ID, clientWithoutRefreshTokenGrant.getClientId()))
                .andExpect(status().isFound())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).getFirst();

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(APPLICATION_JSON_VALUE)
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(OAuth2Utils.CLIENT_ID, clientWithoutRefreshTokenGrant.getClientId())
                .param("client_secret", "secret")
                .param("code", code);

        MvcResult mvcResult = mockMvc.perform(oauthTokenPost).andReturn();
        assertThat(JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), Map.class)).containsKey("access_token")
                .doesNotContainKey("refresh_token");
    }

    @Test
    void refreshAccessToken_withClient_withAutoApproveField() throws Exception {
        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
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
        String code = ((List<String>) query.get("code")).getFirst();
        state = ((List<String>) query.get("state")).getFirst();

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
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
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
        assertThat(url).startsWith(UaaUrlUtils.addQueryParameter(TEST_REDIRECT_URI, "error", "login_required"));
    }

    @Test
    void authorizeEndpointWithPromptNoneForcePasswordChangeRequired() throws Exception {
        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Collections.singletonList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer, true, "pwd", "otp");

        String state = generator.generate();

        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                        .session(session)
                        .param(RESPONSE_TYPE, "code")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                        .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();

        String url = result.getResponse().getHeader("Location");
        assertThat(url).startsWith(UaaUrlUtils.addQueryParameter(TEST_REDIRECT_URI, "error", "interaction_required"));

        setAuthentication(session, developer, false, "pwd", "otp");
        result = mockMvc.perform(get("/oauth/authorize")
                        .session(session)
                        .param(RESPONSE_TYPE, "code")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                        .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
                .andDo(print())
                .andExpect(status().isFound())
                .andReturn();
        url = result.getResponse().getHeader("Location");
        assertThat(url).contains(TEST_REDIRECT_URI)
                .doesNotContain("error")
                .doesNotContain("login_required")
                .doesNotContain("interaction_required");
    }

    @Test
    void authorizeEndpointWithPromptNoneAuthenticated() throws Exception {
        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
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
        assertThat(url).contains(TEST_REDIRECT_URI);
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

        assertThat(result.getResponse().getContentAsString()).contains("[something_else] is invalid. This user is not allowed any of the requested scopes");
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
    void clientIdentityProviderWithoutAllowedProvidersForPasswordGrantWorksInOtherZone() throws Exception {
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
        long delayTime = 15;
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());

        String accessToken = getAccessTokenForPasswordGrant(username);
        Long firstTimestamp = getPreviousLogonTime(accessToken);
        //simulate two sequential tests
        //on a fast processor, there isn't enough granularity in the time
        Thread.sleep(delayTime);
        String accessToken2 = getAccessTokenForPasswordGrant(username);
        Long secondTimestamp = getPreviousLogonTime(accessToken2);

        assertThat(secondTimestamp).isNotEqualTo(firstTimestamp);
        assertThat(firstTimestamp).isLessThan(secondTimestamp);
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

        assertThat(userInfoResponse).isNotNull();
        userInfo = JsonUtils.readValue(userInfoResponse, UserInfoResponse.class);
        return userInfo.getPreviousLogonSuccess();
    }

    @Test
    void clientIdentityProviderClientWithoutAllowedProvidersForAuthCodeAlreadyLoggedInWorksInAnotherZone() throws Exception {
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
        assertThat(query).containsKey("code");
        String code = ((List<String>) query.get("code")).getFirst();
        assertThat(code).isNotNull();
    }

    @Test
    void clientIdentityProviderRestrictionForPasswordGrant() throws Exception {
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
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

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
    void oauth_authorize_api_endpoint() throws Exception {
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
                .param(RESPONSE_TYPE, "code")
                .param(SCOPE, "")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId);
        MvcResult result = mockMvc.perform(oauthAuthorizeGet).andExpect(status().is3xxRedirection()).andReturn();

        String location = result.getResponse().getHeader("Location");
        assertThat(location).as("Location must be present").isNotNull()
                .as("Location must have a code parameter.").contains("code=");

        URL url = new URL(location);
        Map query = splitQuery(url);
        assertThat(query).containsKey("code");
        String code = ((List<String>) query.get("code")).getFirst();
        assertThat(code).isNotNull();

        String body = mockMvc.perform(post("/oauth/token")
                        .with(httpBasic(clientId, SECRET))
                        .header("Host", subdomain + ".localhost")
                        .accept(APPLICATION_JSON)
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param("code", code))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // zone context needs to be set again because MVC calls mutate it
        IdentityZoneHolder.set(testZone);

        assertThat(body).as("Token body must not be null.").isNotNull()
                .contains(ACCESS_TOKEN, REFRESH_TOKEN);
        Map<String, Object> map = JsonUtils.readValue(body, new TypeReference<>() {
        });
        String accessToken = (String) map.get("access_token");
        OAuth2Authentication token = tokenServices.loadAuthentication(accessToken);
        assertThat(token.getOAuth2Request().getScope()).as("Must have uaa.user scope").contains("uaa.user");
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
                .param(GRANT_TYPE, "password");
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(token).containsKey("access_token")
                .containsKey(REFRESH_TOKEN);
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

    private DisableIdTokenResponseTypeFilter getDisableIdTokenResponseFilter() {
        FilterRegistrationBean<DisableIdTokenResponseTypeFilter> bean =
                (FilterRegistrationBean<DisableIdTokenResponseTypeFilter>)
                        webApplicationContext.getBean("disableIdTokenResponseFilter", FilterRegistrationBean.class);
        return bean.getFilter();
    }

    @Test
    void openIdTokenHybridFlowWithNoImplicitGrantWhenIdTokenDisabled() throws Exception {
        try {
            getDisableIdTokenResponseFilter().setIdTokenDisabled(true);

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
                    .param(RESPONSE_TYPE, "code id_token")
                    .param(SCOPE, "openid")
                    .param(OAuth2Utils.STATE, state)
                    .param(OAuth2Utils.CLIENT_ID, clientId)
                    .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

            MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
            String location = result.getResponse().getHeader("Location");
            assertThat(location).doesNotContain("#");
            URL url = new URL(location);
            Map query = splitQuery(url);
            assertThat(query).containsKey("code")
                    .doesNotContainKey("id_token");
            String code = ((List<String>) query.get("code")).getFirst();
            assertThat(code).isNotNull();
        } finally {
            getDisableIdTokenResponseFilter().setIdTokenDisabled(false);
        }
    }

    @Test
    void openIdTokenHybridFlowWithNoImplicitGrant() throws Exception {
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
        assertThat(location).contains("#");
        URL url = new URL(location.replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        assertThat(((List) query.get("id_token")).getFirst()).isNotNull();
        assertThat(((List) query.get("code")).getFirst()).isNotNull();
        assertThat(query).doesNotContainKey("token");
    }

    @Test
    void prompt_is_none_and_approvals_are_required() throws Exception {
        String redirectUrl = TEST_REDIRECT_URI + "#test=true";
        String clientId = "testclient" + new AlphanumericRandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "implicit,authorization_code", false);
        String username = "testuser" + new AlphanumericRandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = new AlphanumericRandomValueStringGenerator().generate();

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
    void openIdTokenHybridFlowWithNoImplicitGrantWhenLenientWhenAppNotApproved() throws Exception {
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
        assertThat(query).containsKey("code");
        String code = ((List<String>) query.get("code")).getFirst();
        assertThat(code).isNotNull();
    }

    @Test
    void openIdTokenHybridFlowWithNoImplicitGrantWhenStrictWhenAppNotApproved() throws Exception {
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
        assertThat(query).containsKey("id_token")
                .doesNotContainKey("token");
        assertThat(((List) query.get("id_token")).getFirst()).isNotNull();
        assertThat(((List) query.get("code")).getFirst()).isNotNull();
    }

    @Test
    void subdomain_redirect_url() throws Exception {
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
        assertThat(location).isEqualTo(subDomainUri);
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
        String errorMessage = UriUtils.encodeQuery("scim.write is invalid. Please use a valid scope name in the request", Charset.defaultCharset());
        assertThat(queryParams).doesNotContainKey("scope");
        assertThat(queryParams.getFirst("error_description")).isEqualTo(errorMessage);
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
        String errorMessage = UriUtils.encodeQuery("[something.else] is invalid. This user is not allowed any of the requested scopes", Charset.defaultCharset());
        assertThat(queryParams).doesNotContainKey("scope");
        assertThat(queryParams.getFirst("error_description")).isEqualTo(errorMessage);
    }

    @Test
    void ensure_that_form_redirect_is_not_a_parameter_unless_there_is_a_saved_request() throws Exception {
        //make sure we don't create a session on the homepage
        assertThat(mockMvc.perform(
                        get("/login")
                )
                .andDo(print())
                .andExpect(content().string(not(containsString(FORM_REDIRECT_PARAMETER))))
                .andReturn().getRequest().getSession(false)).isNull();

        //if there is a session, but no saved request
        mockMvc.perform(
                        get("/login")
                                .session(new MockHttpSession())
                )
                .andDo(print())
                .andExpect(content().string(not(containsString(FORM_REDIRECT_PARAMETER))));
    }

    @Test
    void authorization_code_grant_session_expires_during_app_approval() throws Exception {
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

        mockMvc.perform(get(new URI(url))
                        .session(session))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/oauth/confirm_access"))
                .andExpect(model().attribute("original_uri", "http://localhost" + url))
                .andReturn();
    }

    @Test
    void authorization_code_grant_redirect_when_session_expires() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";

        String clientId = "authclient-" + generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser" + generator.generate();
        String userScopes = "openid";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String state = generator.generate();

        String authUrl = "http://localhost" + UriComponentsBuilder
                .fromUriString("/oauth/authorize?response_type=code&scope=openid&state={state}&client_id={clientId}&redirect_uri={redirectUri}")
                .buildAndExpand(state, clientId, redirectUri)
                .encode()
                .toUri();

        String encodedRedirectUri = UriUtils.encodeQueryParam(redirectUri, "ISO-8859-1");

        MvcResult result = mockMvc
                .perform(get(new URI(authUrl)))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location).endsWith("/login");

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).isNotNull();
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        assertThat(savedRequest).isNotNull();
        assertThat(savedRequest.getRedirectUrl()).isEqualTo(authUrl);

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
        assertThat(session).isNotNull();
        savedRequest = SessionUtils.getSavedRequestSession(session);
        assertThat(savedRequest).isNotNull();

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
    void missing_redirect_uri() throws Exception {

        test_invalid_registered_redirect_uris(emptySet(), status().isBadRequest());
    }

    @Test
    void invalid_redirect_uri() throws Exception {
        test_invalid_registered_redirect_uris(new HashSet<>(Arrays.asList("*", "*/*")), status().isBadRequest());
    }

    @Test
    void valid_redirect_uri() throws Exception {
        String redirectUri = "https://example.com/**";
        test_invalid_registered_redirect_uris(new HashSet<>(Collections.singletonList(redirectUri)), status().isFound());
    }

    @Test
    void authorizationCodeGrantWithEncodedRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=%7B%22orgGuid%22%3A%22org-guid%22%2C%22spaceGuid%22%3A%22space-guid%22%2C%22appGuid%22%3A%22app-guid%22%2C%22redirect%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D";
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
        assertThat(location).isEqualTo(redirectUri);
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

        Map<String, Object> tokenResponse = JsonUtils.readValue(tokenString, new TypeReference<>() {
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
    void authorizationCodeShouldNotThrow500IfClientDoesntExist() throws Exception {
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
        HttpSession session = result.getRequest().getSession(false);

        MockHttpServletRequestBuilder login = get("/login")
                .accept(MediaType.TEXT_HTML)
                .session((MockHttpSession) session);
        mockMvc.perform(login).andExpect(status().isOk());
    }

    @Test
    void implicitGrantWithFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid#test";
        testImplicitGrantRedirectUri(redirectUri, false);
    }

    @Test
    void implicitGrantWithNoFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        testImplicitGrantRedirectUri(redirectUri, false);
    }

    @Test
    void implicitGrantWithFragmentInRedirectURLAndNoPrompt() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid#test";
        testImplicitGrantRedirectUri(redirectUri, true);
    }

    @Test
    void implicitGrantWithNoFragmentInRedirectURLAndNoPrompt() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        testImplicitGrantRedirectUri(redirectUri, true);
    }

    @Test
    void wildcardRedirectURL() throws Exception {
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
                .param(GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("username", developer.getUserName())
                .param("password", SECRET)
                .param(SCOPE, "openid");

        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(token).containsKey(ACCESS_TOKEN)
                .containsKey(REFRESH_TOKEN)
                .isNotNull().doesNotContainEntry("id_token", token.get(ACCESS_TOKEN));
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
                        .param(GRANT_TYPE, "password")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param("username", developer.getUserName())
                        .param("password", SECRET)
                        .param("client_id", clientId)
                        .param("client_secret", SECRET)
                        .param(SCOPE, "openid"))
                .andExpect(status().isOk())
                .andReturn();

        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(token).containsKey(ACCESS_TOKEN)
                .containsKey(REFRESH_TOKEN)
                .doesNotContainEntry("id_token", token.get(ACCESS_TOKEN));
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
        String credentials = "{ \"username\":\"%s\", \"password\":\"%s\" }".formatted(developer.getUserName(), SECRET);
        MvcResult result = mockMvc.perform(post("/oauth/authorize")
                        .header("Accept", "application/json")
                        .param(RESPONSE_TYPE, "token id_token")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                        .param("credentials", credentials)
                        .param(OAuth2Utils.STATE, "random-state")
                        .param(SCOPE, "openid"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertThat(hashFragmentParams.get("access_token").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("id_token").getFirst()).isNotNull()
                .isNotEqualTo(hashFragmentParams.get("access_token").getFirst());
        validateOpenIdConnectToken(hashFragmentParams.get("id_token").getFirst(), developer.getId(), clientId);
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
                        .param(RESPONSE_TYPE, "code")
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(ClaimConstants.NONCE, "testnonce")
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location"));
        Map<String, List<String>> authorizeRedirectQueryParams = splitQuery(url);
        String returnedState = authorizeRedirectQueryParams.get(OAuth2Utils.STATE).getFirst();
        assertThat(returnedState).isEqualTo(state);
        String code = authorizeRedirectQueryParams.get("code").getFirst();
        assertThat(code).isNotNull();

        result = mockMvc.perform(post("/oauth/token")
                        .header("Authorization", "Basic "
                                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param("code", code)
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(tokenResponse).containsKey(ACCESS_TOKEN)
                .containsKey(REFRESH_TOKEN)
                .containsKey("id_token");
        if (authorizeRedirectQueryParams.get("id_token") != null) {
            assertThat(authorizeRedirectQueryParams.get("id_token").getFirst()).isNotEqualTo(tokenResponse.get(ACCESS_TOKEN));
        }
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        //nonce must be in id_token if was in auth request, see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        assertThat(claims).containsEntry(ClaimConstants.NONCE, "testnonce");
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
                        .param(RESPONSE_TYPE, "code id_token token")
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(ClaimConstants.NONCE, "testnonce")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertThat(hashFragmentParams.get("token_type").getFirst()).isEqualTo("bearer");
        assertThat(hashFragmentParams.get("access_token").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("id_token").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("code").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("state").getFirst()).isEqualTo(state);
        assertThat(hashFragmentParams.get("expires_in").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("nonce").getFirst()).isEqualTo("testnonce");
        assertThat(hashFragmentParams.get("jti").getFirst()).isNotNull();
        validateOpenIdConnectToken(hashFragmentParams.get("id_token").getFirst(), developer.getId(), clientId);
        String code = hashFragmentParams.get("code").getFirst();

        result = mockMvc.perform(post("/oauth/token")
                        .header("Authorization", "Basic "
                                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param("code", code)
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(tokenResponse).containsKey(ACCESS_TOKEN);
        assertThat(hashFragmentParams.get(ACCESS_TOKEN).getFirst()).isNotEqualTo(tokenResponse.get(ACCESS_TOKEN));
        assertThat(tokenResponse).containsKey(REFRESH_TOKEN)
                .doesNotContainEntry("id_token", tokenResponse.get(ACCESS_TOKEN));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertThat(claims).containsEntry(ClaimConstants.NONCE, "testnonce");
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
                        .param(RESPONSE_TYPE, "code id_token")
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(ClaimConstants.NONCE, "testnonce")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertThat(hashFragmentParams.get("token_type").getFirst()).isEqualTo("bearer");
        assertThat(hashFragmentParams).doesNotContainKey("access_token");
        assertThat(hashFragmentParams.get("id_token").getFirst()).isNotNull();
        validateOpenIdConnectToken(hashFragmentParams.get("id_token").getFirst(), developer.getId(), clientId);
        assertThat(hashFragmentParams.get("code").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("state").getFirst()).isEqualTo(state);
        assertThat(hashFragmentParams.get("expires_in").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("nonce").getFirst()).isEqualTo("testnonce");
        assertThat(hashFragmentParams.get("jti").getFirst()).isNotNull();
        String code = hashFragmentParams.get("code").getFirst();

        result = mockMvc.perform(post("/oauth/token")
                        .header("Authorization", "Basic "
                                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param("code", code)
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(tokenResponse).containsKey(ACCESS_TOKEN);
        if (hashFragmentParams.get(ACCESS_TOKEN) != null) {
            assertThat(hashFragmentParams.get(ACCESS_TOKEN).getFirst()).isNotEqualTo(tokenResponse.get(ACCESS_TOKEN));
        }
        assertThat(tokenResponse).containsKey(REFRESH_TOKEN)
                .doesNotContainEntry("id_token", tokenResponse.get(ACCESS_TOKEN));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertThat(claims).containsEntry(ClaimConstants.NONCE, "testnonce");
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
                        .param(RESPONSE_TYPE, "code token")
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(ClaimConstants.NONCE, "testnonce")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertThat(hashFragmentParams.get("token_type").getFirst()).isEqualTo("bearer");
        assertThat(hashFragmentParams.get("access_token").getFirst()).isNotNull();
        assertThat(hashFragmentParams).doesNotContainKey("id_token");
        assertThat(hashFragmentParams.get("code").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("state").getFirst()).isEqualTo(state);
        assertThat(hashFragmentParams.get("expires_in").getFirst()).isNotNull();
        assertThat(hashFragmentParams.get("nonce").getFirst()).isEqualTo("testnonce");
        assertThat(hashFragmentParams.get("jti").getFirst()).isNotNull();
        String code = hashFragmentParams.get("code").getFirst();

        result = mockMvc.perform(post("/oauth/token")
                        .header("Authorization", "Basic "
                                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param("code", code)
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(tokenResponse).containsKey(ACCESS_TOKEN);
        assertThat(hashFragmentParams.get(ACCESS_TOKEN).getFirst()).isNotEqualTo(tokenResponse.get(ACCESS_TOKEN));
        assertThat(tokenResponse).containsKey(REFRESH_TOKEN)
                .doesNotContainEntry("id_token", tokenResponse.get(ACCESS_TOKEN));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertThat(claims).containsEntry(ClaimConstants.NONCE, "testnonce");
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
                        .param(RESPONSE_TYPE, "code")
                        .param(SCOPE, "openid")
                        .param(OAuth2Utils.STATE, state)
                        .param(ClaimConstants.NONCE, "testnonce")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirectUri = result.getResponse().getHeader("Location");
        assertThat(redirectUri).as("Redirect URL should not be a fragment.").doesNotContain("#")
                .as("Redirect URL should contain query params.").contains("?");
        Map<String, List<String>> queryParams = splitQuery(new URL(redirectUri));
        assertThat(queryParams.get("state").getFirst()).isEqualTo(state);
        assertThat(queryParams.get("code").getFirst()).isNotNull();
        String code = queryParams.get("code").getFirst();

        result = mockMvc.perform(post("/oauth/token")
                        .header("Authorization", "Basic "
                                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                        .accept(APPLICATION_JSON)
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                        .param("code", code)
                        .param(OAuth2Utils.STATE, state))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(tokenResponse).containsKey(ACCESS_TOKEN);
        if (queryParams.get(ACCESS_TOKEN) != null) {
            assertThat(queryParams.get(ACCESS_TOKEN).getFirst()).isNotEqualTo(tokenResponse.get(ACCESS_TOKEN));
        }
        assertThat(tokenResponse).containsKey(REFRESH_TOKEN)
                // Successful OIDC token response should include ID Token even when scope=openid is not present.
                // http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
                .as("ID Token should be present when client has openid scope")
                .isNotNull()
                .doesNotContainEntry("id_token", tokenResponse.get(ACCESS_TOKEN));
        validateOpenIdConnectToken(tokenResponse.get("id_token"), developer.getId(), clientId);
        Map<String, Object> claims = getClaimsForToken(tokenResponse.get("id_token"));
        assertThat(claims).containsEntry(ClaimConstants.NONCE, "testnonce");
        assertThat(((ArrayList<String>) getClaimsForToken(tokenResponse.get(ACCESS_TOKEN)).get("scope")).getFirst()).isEqualTo("openid");
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
                        .param(RESPONSE_TYPE, "code")
                        .param(SCOPE, "not-openid foo.read")
                        .param(OAuth2Utils.STATE, state)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirectUri = result.getResponse().getHeader("Location");
        assertThat(redirectUri).as("Redirect URL should not be a fragment.").doesNotContain("#")
                .as("Redirect URL should contain query params.").contains("?");
        Map<String, List<String>> queryParams = splitQuery(new URL(redirectUri));
        assertThat(queryParams.get("state").getFirst()).isEqualTo(state);
        assertThat(queryParams.get("code").getFirst()).isNotNull();
        String code = queryParams.get("code").getFirst();

        result = mockMvc.perform(post("/oauth/token")
                        .header("Authorization", "Basic "
                                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                        .accept(APPLICATION_JSON)
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                        .param("code", code)
                        .param(OAuth2Utils.STATE, state))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(tokenResponse).containsKey(ACCESS_TOKEN);
        if (queryParams.get(ACCESS_TOKEN) != null) {
            assertThat(queryParams.get(ACCESS_TOKEN).getFirst()).isNotEqualTo(tokenResponse.get(ACCESS_TOKEN));
        }
        assertThat(((ArrayList<String>) getClaimsForToken(tokenResponse.get(ACCESS_TOKEN)).get("scope")).getFirst()).isEqualTo("not-openid");

        assertThat(tokenResponse).containsKey(REFRESH_TOKEN)
                // Successful OIDC token response should include ID Token even when scope=openid is not present.
                // http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
                .as("ID Token should not be present when client is missing openid scope")
                .doesNotContainKey("id_token");
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
                        .param(RESPONSE_TYPE, "code")
                        .param(OAuth2Utils.STATE, "random-state")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> hashFragmentParams = splitQuery(url);
        assertThat(hashFragmentParams).containsKey(OAuth2Utils.STATE);
        assertThat(hashFragmentParams.get(OAuth2Utils.STATE).getFirst()).isEqualTo("random-state");
        String code = hashFragmentParams.get("code").getFirst();
        assertThat(code).isNotNull();

        result = mockMvc.perform(post("/oauth/token")
                        .accept(APPLICATION_JSON)
                        .header("Authorization", "Basic "
                                + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes())))
                        .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                        .param("code", code))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, String> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(tokenResponse).as("ID Token should be present when response_type includes id_token")
                .containsKey("id_token")
                .containsKey("access_token");
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
                        .param(RESPONSE_TYPE, "id_token")
                        .param(OAuth2Utils.STATE, "random-state")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#", "redirect?"));
        Map<String, List<String>> tokenResponse = splitQuery(url);
        assertThat(tokenResponse).containsKey(OAuth2Utils.STATE)
                .containsKey("id_token");
        assertThat(tokenResponse.get(OAuth2Utils.STATE).getFirst()).isEqualTo("random-state");
    }

    @Test
    void token_expiry_time() throws Exception {
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain, new ArrayList<>(defaultAuthorities));
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, null, null, 60 * 60 * 24 * 3650);

        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

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

        Map<String, Object> claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<>() {
        });
        Integer expirationTime = (Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS);

        Calendar nineYearsAhead = new GregorianCalendar();
        nineYearsAhead.setTimeInMillis(System.currentTimeMillis());
        nineYearsAhead.add(Calendar.YEAR, 9);
        assertThat(new Date(expirationTime * 1000L).after(new Date(nineYearsAhead.getTimeInMillis()))).as("Expiration Date should be more than 9 years ahead.").isTrue();
    }

    @Test
    void required_user_groups_password_grant() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "*.*";
        Map<String, Object> additional = new HashMap<>();
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
    void wildcardPasswordGrant() throws Exception {
        String subdomain = "testzone" + generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain, new ArrayList<>(defaultAuthorities));
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

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
    void loginAddNewUserForOauthTokenPasswordGrant() throws Exception {
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
        assertThat(user).isNotNull();
        assertThat(user.getUsername()).isEqualTo(username);
        assertThat(user.getEmail()).isEqualTo(email);
        assertThat(user.getGivenName()).isEqualTo(first);
        assertThat(user.getFamilyName()).isEqualTo(last);
    }

    @Test
    void loginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.LOGIN_SERVER, IdentityZoneHolder.get().getId());
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");
        String basicAuthForLoginClient = new String(Base64.encode("%s:%s".formatted("login", "loginsecret").getBytes()));

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
    void otherOauthResourceLoginAuthenticationFilter() throws Exception {
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
    void otherClientAuthenticationMethods() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String oauthClientId = "testclient" + generator.generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something,uaa.user";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES, true);

        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,uaa.user";
        ScimUser developer = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String basicAuthForOauthClient = new String(Base64.encode("%s:%s".formatted(oauthClientId, SECRET).getBytes()));

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
    void getClientCredentialsTokenForDefaultIdentityZone() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                        .accept(APPLICATION_JSON_VALUE)
                        .with(httpBasic(clientId, SECRET))
                        .param("grant_type", "client_credentials")
                        .param("client_id", clientId)
                        .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
        });
        assertThat(bodyMap).containsKey("access_token");
        Jwt jwt = JwtHelper.decode((String) bodyMap.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<>() {
        });
        assertThat(claims).containsKey(ClaimConstants.AUTHORITIES)
                .containsKey(ClaimConstants.AZP)
                .doesNotContainKey(ClaimConstants.USER_ID);
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

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
        });
        String accessToken = (String) bodyMap.get("access_token");
        assertThat(accessToken).isNotNull();

        clientDetailsService.addClientSecret(clientId, "newSecret", IdentityZoneHolder.get().getId());
        mockMvc.perform(post("/check_token")
                        .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                        .param("token", accessToken))
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

            Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
            });
            String accessToken = (String) bodyMap.get("access_token");
            assertThat(accessToken).isNotNull();

            mockMvc.perform(post("/check_token")
                            .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                            .param("token", accessToken))
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

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
        });
        String accessToken = (String) bodyMap.get("access_token");
        assertThat(accessToken).isNotNull();

        clientDetailsService.addClientSecret(clientId, "newSecret", IdentityZoneHolder.get().getId());
        clientDetailsService.deleteClientSecret(clientId, IdentityZoneHolder.get().getId());

        MockHttpServletResponse response = mockMvc.perform(post("/check_token")
                        .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                        .param("token", accessToken))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse();

        InvalidTokenException tokenRevokedException = JsonUtils.readValue(response.getContentAsString(), TokenRevokedException.class);
        assertThat(tokenRevokedException.getOAuth2ErrorCode()).isEqualTo("invalid_token");
        assertThat(tokenRevokedException.getMessage()).isEqualTo("revocable signature mismatch");
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

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
        });
        String accessToken = (String) bodyMap.get("access_token");
        assertThat(accessToken).isNotNull();

        clientDetailsService.deleteClientSecret(clientId, IdentityZoneHolder.get().getId());
        mockMvc.perform(post("/check_token")
                        .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                        .param("token", accessToken))
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

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
        });
        String accessToken = (String) bodyMap.get("access_token");
        assertThat(accessToken).isNotNull();

        mockMvc.perform(post("/check_token")
                        .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                        .param("token", accessToken))
                .andExpect(status().isOk());
    }

    @Test
    void getClientCredentialsWithAuthoritiesExcludedForDefaultIdentityZone() throws Exception {
        Set<String> originalExclude = webApplicationContext.getBean(UaaTokenServices.class).getExcludedClaims();
        try {
            webApplicationContext.getBean(UaaTokenServices.class).setExcludedClaims(new HashSet<>(Arrays.asList(ClaimConstants.AUTHORITIES, ClaimConstants.AZP)));
            String clientId = "testclient" + generator.generate();
            String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
            setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

            String body = mockMvc.perform(post("/oauth/token")
                            .accept(APPLICATION_JSON_VALUE)
                            .with(httpBasic(clientId, SECRET))
                            .param("grant_type", "client_credentials")
                            .param("client_id", clientId)
                            .param("client_secret", SECRET))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
            });
            assertThat(bodyMap).containsKey("access_token");
            Jwt jwt = JwtHelper.decode((String) bodyMap.get("access_token"));
            Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<>() {
            });
            assertThat(claims).doesNotContainKey(ClaimConstants.AUTHORITIES)
                    .doesNotContainKey(ClaimConstants.AZP);
        } finally {
            webApplicationContext.getBean(UaaTokenServices.class).setExcludedClaims(originalExclude);
        }
    }

    @Test
    void getClientCredentialsTokenForOtherIdentityZone() throws Exception {
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
    void getClientCredentialsTokenForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
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
    void getClientCredentialsTokenForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
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
    void getPasswordGrantInvalidPassword() throws Exception {
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
                .andExpect(content().string("{\"error\":\"invalid_client\",\"error_description\":\"Bad credentials\"}"));
    }

    @Test
    void getPasswordGrantTokenExpiredPasswordForOtherZone() throws Exception {
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
        assertThat(webApplicationContext.getBean(JdbcTemplate.class).update("UPDATE users SET passwd_lastmodified = ? WHERE username = ?", t, username)).isOne();

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
        List<String> defaultGroups = new LinkedList<>(List.of("custom.default.group", "other.default.group"));
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
        Claims claims = UaaTokenUtils.getClaimsFromTokenString(JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class).accessToken);
        assertThat("http://" + subdomain.toLowerCase() + ".localhost:8080/uaa/oauth/token").isEqualTo(claims.getIss());
        assertThat(claims.getScope()).containsExactlyInAnyOrder("openid", "custom.default.group");
    }

    @Test
    void getPasswordGrantTokenForOtherZone() throws Exception {
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
        Claims claims = UaaTokenUtils.getClaimsFromTokenString(JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class).accessToken);
        assertThat("http://" + subdomain.toLowerCase() + ".localhost:8080/uaa/oauth/token").isEqualTo(claims.getIss());
    }

    @Test
    void getPasswordGrantForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
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
    void getPasswordGrantForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
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
    void getTokenScopesNotInAuthentication() throws Exception {
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
                .param(RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
        String code = builder.build().getQueryParams().get("code").getFirst();

        authRequest = post("/oauth/token")
                .with(httpBasic(clientId, SECRET))
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Host", subdomain + ".localhost")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        result = mockMvc.perform(authRequest).andDo(print()).andExpect(status().is2xxSuccessful()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);

        IdentityZoneHolder.set(testZone);
        OAuth2Authentication authContext = tokenServices.loadAuthentication(oauthToken.accessToken);

        assertThat(authContext.getOAuth2Request().getScope())
                .hasSize(4)
                .containsExactlyInAnyOrder(zoneAdminGroup, "openid", "cloud_controller.read", "cloud_controller.write");
    }

    @Test
    void getTokenPromptLogin() throws Exception {
        ScimUser user = setUpUser(generator.generate() + "@test.org");

        String zoneadmingroup = "zones." + generator.generate() + ".admin";
        ScimGroup group = new ScimGroup(null, zoneadmingroup, IdentityZone.getUaaZoneId());
        group = jdbcScimGroupProvisioning.create(group, IdentityZoneHolder.get().getId());
        ScimGroupMember member = new ScimGroupMember(user.getId());
        jdbcScimGroupMembershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(user);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Authorization", "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64("identity:identitysecret".getBytes())))
                .header("Accept", APPLICATION_JSON_VALUE)
                .session(session)
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param("prompt", "login")
                .param(OAuth2Utils.CLIENT_ID, "identity")
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        assertThat(result.getResponse().getRedirectedUrl().split("\\?")[0]).isEqualTo(result.getRequest().getRequestURL().toString());
        Map<String, String[]> mapRequest = result.getRequest().getParameterMap();
        Map<String, String[]> mapResponse = UaaUrlUtils.getParameterMap(result.getResponse().getRedirectedUrl());
        for (String key : mapResponse.keySet()) {
            assertThat(mapRequest).containsKey(key);
            assertThat(mapResponse.get(key)).containsExactly(mapRequest.get(key));
        }
        Set<String> requestKeys = new HashSet<>(mapRequest.keySet());
        requestKeys.removeAll(mapResponse.keySet());
        assertThat(requestKeys).hasSize(1)
                .contains("prompt");
    }

    @Test
    void getTokenMaxAge() throws Exception {

        ScimUser user = setUpUser(generator.generate() + "@test.org");

        String zoneadmingroup = "zones." + generator.generate() + ".admin";
        ScimGroup group = new ScimGroup(null, zoneadmingroup, IdentityZone.getUaaZoneId());
        group = jdbcScimGroupProvisioning.create(group, IdentityZoneHolder.get().getId());
        ScimGroupMember member = new ScimGroupMember(user.getId());
        jdbcScimGroupMembershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(user);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .header("Authorization", "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64("identity:identitysecret".getBytes())))
                .header("Accept", APPLICATION_JSON_VALUE)
                .session(session)
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param("max_age", "1")
                .param(OAuth2Utils.CLIENT_ID, "identity")
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        assertThat(result.getResponse().getRedirectedUrl().split("\\?")[0]).isEqualTo("http://localhost/test");
        Thread.sleep(2000);

        authRequest = get("/oauth/authorize")
                .header("Authorization", "Basic " + new String(org.apache.commons.codec.binary.Base64.encodeBase64("identity:identitysecret".getBytes())))
                .header("Accept", APPLICATION_JSON_VALUE)
                .session(session)
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param(RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param("max_age", "1")
                .param(OAuth2Utils.CLIENT_ID, "identity")
                .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        result = mockMvc.perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        assertThat(result.getResponse().getRedirectedUrl().split("\\?")[0]).isEqualTo(result.getRequest().getRequestURL().toString());
        Map<String, String[]> mapRequest = result.getRequest().getParameterMap();
        Map<String, String[]> mapResponse = UaaUrlUtils.getParameterMap(result.getResponse().getRedirectedUrl());
        for (String key : mapResponse.keySet()) {
            assertThat(mapRequest).containsKey(key);
            assertThat(mapResponse.get(key)).containsExactly(mapRequest.get(key));
        }
        Set<String> requestKeys = new HashSet<>(mapRequest.keySet());
        requestKeys.removeAll(mapResponse.keySet());
        assertThat(requestKeys).hasSize(1)
                .contains("max_age");
    }

    @Test
    void revocablePasswordGrantTokenForDefaultZone() throws Exception {
        String tokenKey = "access_token";
        Map<String, Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(new HashedMap());
        assertThat(tokenResponse).as("Token must be present").containsKey(tokenKey);
        assertThat(tokenResponse.get(tokenKey)).as("Token must be a string").isInstanceOf(String.class);
        String token = (String) tokenResponse.get(tokenKey);
        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<>() {
        });
        assertThat(claims).as("Token revocation signature must exist").containsKey(ClaimConstants.REVOCATION_SIGNATURE);
        assertThat(claims.get(ClaimConstants.REVOCATION_SIGNATURE)).as("Token revocation signature must be a string").isInstanceOf(String.class);
        assertThat(StringUtils.hasText((String) claims.get(ClaimConstants.REVOCATION_SIGNATURE))).as("Token revocation signature must have data").isTrue();
    }

    @Test
    void passwordGrantTokenForDefaultZoneOpaque() throws Exception {
        Map<String, String> parameters = new HashedMap<>();
        parameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        String tokenKey = "access_token";
        Map<String, Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(parameters);
        assertThat(tokenResponse).as("Token must be present").containsKey(tokenKey);
        assertThat(tokenResponse.get(tokenKey)).as("Token must be a string").isInstanceOf(String.class);
        String token = (String) tokenResponse.get(tokenKey);
        assertThat(token).as("Token must be shorter than 37 characters").hasSizeLessThanOrEqualTo(36);

        RevocableToken revocableToken = webApplicationContext.getBean(RevocableTokenProvisioning.class).retrieve(token, IdentityZoneHolder.get().getId());
        assertThat(revocableToken).as("Token should have been stored in the DB").isNotNull();

        Jwt jwt = JwtHelper.decode(revocableToken.getValue());
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<>() {
        });
        assertThat(claims).as("Revocable claim must exist").containsKey(ClaimConstants.REVOCABLE);
        assertThat((Boolean) claims.get(ClaimConstants.REVOCABLE)).as("Token revocable claim must be set to true").isTrue();
    }

    @Test
    void nonDefaultZoneJwtRevocable() throws Exception {
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
                            .andReturn().getResponse().getContentAsString(), new TypeReference<>() {
                    });
            validateRevocableJwtToken(tokenResponse, defaultZone);
        } finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            zoneProvisioning.update(defaultZone);
        }
    }

    @Test
    void defaultZoneJwtRevocable() throws Exception {
        IdentityZoneProvisioning zoneProvisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        IdentityZone defaultZone = zoneProvisioning.retrieve(IdentityZone.getUaaZoneId());
        try {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
            zoneProvisioning.update(defaultZone);
            Map<String, String> parameters = new HashedMap<>();
            Map<String, Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(parameters);
            validateRevocableJwtToken(tokenResponse, defaultZone);
        } finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            zoneProvisioning.update(defaultZone);
        }
    }

    @Test
    void refreshGrantWithAccessToken() throws Exception {
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

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
        });
        String accessToken = (String) bodyMap.get("access_token");
        assertThat(accessToken).isNotNull();

        doRefreshGrant(accessToken, clientId, SECRET, status().isUnauthorized());
    }

    @Test
    void refreshGrantReturnsValidAccessToken() throws Exception {
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

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<>() {
        });
        String refreshToken = (String) bodyMap.get("refresh_token");

        assertThat(refreshToken).isNotNull();

        body = doRefreshGrant(refreshToken, clientId, SECRET, status().isOk()).getResponse().getContentAsString();
        CompositeToken tokenResponse = JsonUtils.readValue(body, CompositeToken.class);
        Map<String, Object> claims = UaaTokenUtils.getClaims(tokenResponse.getValue(), Map.class);

        assertThat(claims.get(JTI).toString()).doesNotEndWith("-r");
    }

    @Test
    void jkuHeaderIsSetAndNonRfcHeadersNotSetForAccessToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(APPLICATION_JSON_VALUE)
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
                JsonUtils.readValue(accessTokenHeaderJson, new TypeReference<>() {
                });

        assertThat(headerMap).containsEntry("jku", "https://localhost:8080/uaa/token_keys")
                // `enc` and `iv` are not required by JWT or OAuth spec, so should not be set and thus not returned in the token's header
                .doesNotContainKey("enc")
                .doesNotContainKey("iv");
    }

    @Test
    void jkuHeaderIsSetAndNonRfcHeadersNotSetForRefreshToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param(CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", "marissa")
                .param("password", "koala")
        ).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        CompositeToken tokenResponse = JsonUtils.readValue(body, CompositeToken.class);
        assertThat(tokenResponse.getRefreshToken()).isNotNull();

        String refreshTokenHeaderRaw = tokenResponse.getRefreshToken().getValue().split("\\.")[0];
        String refreshTokenHeaderJson = new String(java.util.Base64.getDecoder().decode(refreshTokenHeaderRaw));
        Map<String, Object> headerMap =
                JsonUtils.readValue(refreshTokenHeaderJson, new TypeReference<>() {
                });

        assertThat(headerMap).containsEntry("jku", "https://localhost:8080/uaa/token_keys")
                // `enc` and `iv` are not required by JWT or OAuth spec, so should not be set and thus not returned in the token's header
                .doesNotContainKey("enc")
                .doesNotContainKey("iv");
    }

    @Test
    void jkuHeaderIsSetAndNonRfcHeadersNotSetForIdToken() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "uaa.user,openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = mockMvc.perform(post("/oauth/token")
                .accept(APPLICATION_JSON_VALUE)
                .with(httpBasic(clientId, SECRET))
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param(CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", "marissa")
                .param("password", "koala")
                .param("response_type", "id_token")
        ).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        CompositeToken tokenResponse = JsonUtils.readValue(body, CompositeToken.class);
        assertThat(tokenResponse.getIdTokenValue()).isNotNull();

        String idTokenHeaderRaw = tokenResponse.getIdTokenValue().split("\\.")[0];
        String idTokenHeaderJson = new String(java.util.Base64.getDecoder().decode(idTokenHeaderRaw));
        Map<String, Object> headerMap =
                JsonUtils.readValue(idTokenHeaderJson, new TypeReference<>() {
                });

        assertThat(headerMap).containsEntry("jku", "https://localhost:8080/uaa/token_keys")
                // `enc` and `iv` are not required by JWT or OAuth spec, so should not be set and thus not returned in the token's header
                .doesNotContainKey("enc")
                .doesNotContainKey("iv");
    }

    @Test
    void authorizationCanRedirectToSubpathOfConfiguredRedirect() throws Exception {
        String clientId = "testclient" + generator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
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
        assertThat(url).contains(TEST_REDIRECT_URI + "/subpath");
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
        assertThat(grantedScopes).hasSameSizeAs(expectedScopes);
        assertThat(new HashSet<>(expectedScopes)).isEqualTo(grantedScopes);
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
        UaaClientDetails client = setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
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
        assertThat(iss).isEqualTo(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        String sub = (String) result.get(ClaimConstants.SUB);
        assertThat(sub).isEqualTo(userId);
        Object audObject = result.get(ClaimConstants.AUD);
        List<String> aud = new ArrayList<>();
        if (audObject instanceof Collection<?>) {
            aud.addAll((List<String>) result.get(ClaimConstants.AUD));
        } else if (audObject instanceof String audString) {
            aud.add(audString);
        }
        assertThat(aud).contains(clientId);
        Integer exp = (Integer) result.get(ClaimConstants.EXPIRY_IN_SECONDS);
        assertThat(exp).isNotNull();
        Integer iat = (Integer) result.get(ClaimConstants.IAT);
        assertThat(iat).isNotNull();
        assertThat(exp).isGreaterThan(iat);
        List<String> openid = (List<String>) result.get(ClaimConstants.SCOPE);
        assertThat(openid).containsExactlyInAnyOrder("openid");

        Integer authTime = (Integer) result.get(ClaimConstants.AUTH_TIME);
        assertThat(authTime).isNotNull();
        Long previousLogonTime = (Long) result.get(ClaimConstants.PREVIOUS_LOGON_TIME);
        assertThat(previousLogonTime).isNotNull();
        Long dbPreviousLogonTime = webApplicationContext.getBean(UaaUserDatabase.class).retrieveUserById(userId).getPreviousLogonTime();
        assertThat(previousLogonTime).isEqualTo(dbPreviousLogonTime);

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
                .param(RESPONSE_TYPE, "token")
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

        assertThat(locationUri).isEqualTo(redirectUri.split("#")[0]);
        String[] locationParams = locationToken.split("&");
        assertThat(locationParams).contains("token_type=bearer")
                .anyMatch(s -> s.startsWith("access_token="));
    }

    private static void containsExactlyOneInstance(String string, String substring) {
        assertThat(string).contains(substring);
        assertThat(string.lastIndexOf(substring)).isEqualTo(string.indexOf(substring));
    }

    private void logUserInTwice(String userId) {
        // We need to do this so that last logon time and previous logon time are populated on the user
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(userId);
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(userId);
    }

    private void tryLoginWithWrongSecretInHeader(String clientId) throws Exception {
        mockMvc.perform(post("/oauth/token")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .with(httpBasic(clientId, BAD_SECRET))
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
                        .param("client_secret", BAD_SECRET)
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
        assertThat(auth.isAuthenticated()).isTrue();
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
        assertThat(tokenResponse).as("Token must be present").containsKey(tokenKey);
        assertThat(tokenResponse.get(tokenKey)).as("Token must be a string").isInstanceOf(String.class);
        String token = (String) tokenResponse.get(tokenKey);
        assertThat(token).as("Token must be longer than 36 characters").hasSizeGreaterThan(36);

        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<>() {
        });
        assertThat(claims).as("JTI Claim should be present").containsKey(JTI);
        String tokenId = (String) claims.get(JTI);

        IdentityZoneHolder.set(zone);
        RevocableToken revocableToken = webApplicationContext.getBean(RevocableTokenProvisioning.class).retrieve(tokenId, IdentityZoneHolder.get().getId());
        IdentityZoneHolder.clear();
        assertThat(revocableToken).as("Token should have been stored in the DB").isNotNull();

        jwt = JwtHelper.decode(revocableToken.getValue());
        claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<>() {
        });
        assertThat(claims).as("Revocable claim must exist").containsKey(ClaimConstants.REVOCABLE);
        assertThat((Boolean) claims.get(ClaimConstants.REVOCABLE)).as("Token revocable claim must be set to true").isTrue();

        assertThat(revocableToken.getValue()).isEqualTo(token);
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
                        .andReturn().getResponse().getContentAsString(), new TypeReference<>() {
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

        @Serial
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
