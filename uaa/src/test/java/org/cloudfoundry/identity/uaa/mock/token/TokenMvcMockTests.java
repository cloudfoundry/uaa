/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.httpclient.util.URIUtil;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.TokenRevokedException;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenEndpoint;
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
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.xml.ConfigurationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
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
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createClient;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createUser;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setDisableInternalAuth;
import static org.cloudfoundry.identity.uaa.oauth.UaaTokenServicesTests.AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.UaaTokenServicesTests.PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REFRESH_TOKEN_SUFFIX;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.createLocalSamlIdpDefinition;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.SCOPE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenMvcMockTests extends AbstractTokenMockMvcTests {

    private String BADSECRET = "badsecret";
    private TestClient testClient;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private MockEnvironment mockEnvironment;
    private static SamlTestUtils samlTestUtils = new SamlTestUtils();
    private boolean allowQueryString;

    @BeforeClass
    public static void initializeSamlUtils() {
        try {
            samlTestUtils.initializeSimple();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    @Before
    public void setup () throws Exception {
        mockEnvironment = ((MockEnvironment) getWebApplicationContext().getEnvironment());
        allowQueryString = getWebApplicationContext().getBean(UaaTokenEndpoint.class).isAllowQueryString();
    }

    @After
    public void resetAllowQueryString() throws Exception {
        getWebApplicationContext().getBean(UaaTokenEndpoint.class).setAllowQueryString(allowQueryString);
    }

    @Override
    public void setUpContext() throws Exception {
        testClient = new TestClient();

        super.setUpContext();
    }

    @Test
    public void token_endpoint_get_by_default() throws Exception {
        try_token_with_non_post(get("/oauth/token"), status().isOk());
    }

    @Test
    public void token_endpoint_get() throws Exception {
        getWebApplicationContext().getBean(UaaTokenEndpoint.class).setAllowQueryString(false);
        try_token_with_non_post(get("/oauth/token"), status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Request method 'GET' not supported"));

    }

    @Test
    public void token_endpoint_put() throws Exception {
        try_token_with_non_post(put("/oauth/token"), status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Request method 'PUT' not supported"));

    }

    @Test
    public void token_endpoint_delete() throws Exception {
        try_token_with_non_post(delete("/oauth/token"), status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Request method 'DELETE' not supported"));

    }

    @Test
    public void token_endpoint_post() throws Exception {
        try_token_with_non_post(post("/oauth/token"), status().isOk());
    }

    @Test
    public void token_endpoint_post_query_string_by_default() throws Exception {
        String username = setUpUserForPasswordGrant();

        getMockMvc().perform(
            post("/oauth/token?client_id=cf&client_secret=&grant_type=password&username={username}&password=secret", username)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isOk());
    }

    @Test
    public void token_endpoint_post_query_string() throws Exception {
        getWebApplicationContext().getBean(UaaTokenEndpoint.class).setAllowQueryString(false);
        String username = setUpUserForPasswordGrant();

        getMockMvc().perform(
            post("/oauth/token?client_id=cf&client_secret=&grant_type=password&username={username}&password=secret", username)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isNotAcceptable())
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.error").value("query_string_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Parameters must be passed in the body of the request"));
    }



    public ResultActions try_token_with_non_post(MockHttpServletRequestBuilder builder, ResultMatcher status) throws Exception {
        String username = setUpUserForPasswordGrant();

        return getMockMvc().perform(
            builder
                .param("client_id", "cf")
                .param("client_secret", "")
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("username", username)
                .param("password", SECRET)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andDo(print())
            .andExpect(status)
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"));
    }

    @Test
    public void refresh_grant_fails_because_missing_required_groups() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "password,refresh_token", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetailsService.addClientDetails(clientDetails);
        MvcResult result = doPasswordGrant(username, SECRET, clientId, SECRET, status().isOk());

        Map<String,Object> tokenResponse = JsonUtils.readValue(
            result.getResponse().getContentAsString(),
            new TypeReference<Map<String, Object>>() {}
        );

        String refreshToken = (String) tokenResponse.get(REFRESH_TOKEN);
        assertNotNull(refreshToken);

        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("uaa.admin"));
        clientDetailsService.updateClientDetails(clientDetails);

        result = doRefreshGrant(refreshToken, clientId, SECRET, status().isUnauthorized());
        assertThat(result.getResponse().getContentAsString(), containsString("User does not meet the client's required group criteria."));
    }

    @Test
    public void authorization_code_missing_required_scopes() throws Exception {
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code", "uaa.resource", "http://localhost");
        clientDetails.setClientSecret(SECRET);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("uaa.admin"));
        clientDetailsService.addClientDetails(clientDetails);

        String location = getMockMvc().perform(
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
    public void authorization_code_missing_required_scopes_during_token_fetch() throws Exception {
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", "authorization_code", "uaa.resource", "http://localhost");
        clientDetails.setAutoApproveScopes(Arrays.asList("true"));
        clientDetails.setClientSecret(SECRET);
        clientDetailsService.addClientDetails(clientDetails);

        String location = getMockMvc().perform(
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
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("uaa.admin"));
        clientDetailsService.updateClientDetails(clientDetails);

        MvcResult result = getMockMvc().perform(
            post("/oauth/token")
                .param("code", code)
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param(OAuth2Utils.GRANT_TYPE, AUTHORIZATION_CODE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isUnauthorized())
            .andReturn();

        Map<String,Object> errorResponse = JsonUtils.readValue(
            result.getResponse().getContentAsString(),
            new TypeReference<Map<String, Object>>() {}
        );

        assertThat((String)errorResponse.get("error_description"), containsString("User does not meet the client's required group criteria."));
    }

    @Test
    public void token_grant_missing_required_groups() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "password", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("uaa.admin"));
        clientDetailsService.addClientDetails(clientDetails);
        MvcResult result = doPasswordGrant(username, SECRET, clientId, SECRET, status().isBadRequest());
        Map<String,Object> errorResponse = JsonUtils.readValue(
            result.getResponse().getContentAsString(),
            new TypeReference<Map<String, Object>>() {}
        );

        assertThat((String)errorResponse.get("error_description"), containsString("User does not meet the client's required group criteria."));
    }

    @Test
    public void token_grant_required_groups_are_present() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,required.scope.1,required.scope.2";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope,required.scope.1,required.scope.2", "password", "uaa.resource", null);
        clientDetails.setClientSecret(SECRET);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("required.scope.1","required.scope.2"));
        clientDetailsService.addClientDetails(clientDetails);
        doPasswordGrant(username, SECRET, clientId, SECRET, status().isOk());
    }


    @Test
    public void test_logon_timestamps_with_password_grant() throws Exception {
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        ScimUserProvisioning provisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        ScimUser scimUser = provisioning.retrieve(user.getId());
        assertNull(scimUser.getLastLogonTime());
        assertNull(scimUser.getPreviousLogonTime());

        doPasswordGrant(username, SECRET, "cf", "", status().isOk());
        scimUser = provisioning.retrieve(user.getId());
        assertNotNull(scimUser.getLastLogonTime());
        assertNull(scimUser.getPreviousLogonTime());

        long lastLogonTime = scimUser.getLastLogonTime();
        doPasswordGrant(username, SECRET, "cf", "", status().isOk());
        scimUser = provisioning.retrieve(user.getId());
        assertNotNull(scimUser.getLastLogonTime());
        assertNotNull(scimUser.getPreviousLogonTime());
        assertEquals(lastLogonTime, (long)scimUser.getPreviousLogonTime());
        assertTrue(scimUser.getLastLogonTime() > scimUser.getPreviousLogonTime());

    }

    public MvcResult doPasswordGrant(String username,
                                     String password,
                                     String clientId,
                                     String clientSecret,
                                     ResultMatcher resultMatcher) throws Exception {
        return getMockMvc().perform(
            post("/oauth/token")
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("username", username)
                .param("password", password)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(resultMatcher)
            .andReturn();
    }

    public MvcResult doRefreshGrant(String refreshToken,
                                    String clientId,
                                    String clientSecret,
                                    ResultMatcher resultMatcher) throws Exception {
        return getMockMvc().perform(
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

    @Test
    public void passcode_with_client_parameters_when_password_change_required_for_user() throws Exception {
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        userProvisioning.updatePasswordChangeRequired(user.getId(), true);

        String response = getMockMvc().perform(
            post("/oauth/token")
                .param("client_id", "cf")
                .param("client_secret", "")
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("username", username)
                .param("password", SECRET)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();

        Map<String, String> error = (JsonUtils.readValue(response, new TypeReference<Map<String, String>>() {}));
        String error_description = error.get("error_description");
        assertNotNull(error_description);
        assertEquals("User password needs to be changed", error_description);

    }

    @Test
    public void passcode_with_client_parameters() throws Exception {
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String content = getMockMvc().perform(
            get("/passcode")
            .session(getAuthenticatedSession(user))
            .accept(APPLICATION_JSON)
        )
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        String code = JsonUtils.readValue(content, String.class);

        String response = getMockMvc().perform(
            post("/oauth/token")
                .param("client_id", "cf")
                .param("client_secret", "")
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("passcode", code)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {});
        Object accessToken = tokens.get(ACCESS_TOKEN);
        Object jti = tokens.get(JTI);
        assertNotNull(accessToken);
        assertNotNull(JTI);

    }

    @Test
    public void test_encoded_char_on_authorize_url() throws Exception {
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        getMockMvc().perform(
            get("/oauth/authorize")
                .param("client_id", new String(new char[]{'\u0000'}))
                .session(getAuthenticatedSession(user))
                .accept(MediaType.TEXT_HTML))
            .andExpect(status().isBadRequest())
            .andExpect(request().attribute("error_message_code", "request.invalid_parameter"));
    }

    @Test
    public void refresh_access_token_and_user_group_removed() throws Exception {
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user,uaa.admin", "password,refresh_token", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));

        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user,uaa.admin";
        ScimUser scimUser = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String response = getMockMvc().perform(post("/oauth/token")
                                                   .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                                   .param(OAuth2Utils.RESPONSE_TYPE, "token")
                                                   .param(OAuth2Utils.GRANT_TYPE, "password")
                                                   .param(OAuth2Utils.CLIENT_ID, clientId)
                                                   .param(REQUEST_TOKEN_FORMAT, OPAQUE)
                                                   .param("client_secret", SECRET)
                                                   .param("username", username)
                                                   .param("password", SECRET))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {});
        String scopes = (String) tokens.get(SCOPE);
        assertThat(scopes, containsString("uaa.admin"));
        Object refreshToken = tokens.get(REFRESH_TOKEN);
        String refreshTokenId = (String) refreshToken;

        List<ScimGroup> groups = getWebApplicationContext().getBean(ScimGroupProvisioning.class).query("displayName eq \"uaa.admin\"");
        assertEquals(1, groups.size());
        getWebApplicationContext().getBean(ScimGroupMembershipManager.class).removeMemberById(groups.get(0).getId(), scimUser.getId());

        getMockMvc().perform(
            post("/oauth/token")
                .header(AUTHORIZATION, "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                .param(REFRESH_TOKEN, refreshTokenId)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE))

            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();
    }


    @Test
    public void test_token_ids() throws Exception {
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "password,refresh_token", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));

        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        String response = getMockMvc().perform(post("/oauth/token")
                                 .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                 .param(OAuth2Utils.RESPONSE_TYPE, "token")
                                 .param(OAuth2Utils.GRANT_TYPE, "password")
                                 .param(OAuth2Utils.CLIENT_ID, clientId)
                                 .param(REQUEST_TOKEN_FORMAT, OPAQUE)
                                 .param("client_secret", SECRET)
                                 .param("username", username)
                                 .param("password", SECRET))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        Map<String,Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {});
        Object accessToken = tokens.get(ACCESS_TOKEN);
        Object refreshToken = tokens.get(REFRESH_TOKEN);
        Object jti = tokens.get(JTI);
        assertNotNull(accessToken);
        assertNotNull(refreshToken);
        assertNotNull(jti);
        assertEquals(jti, accessToken);
        assertNotEquals(accessToken + REFRESH_TOKEN_SUFFIX, refreshToken);
        String accessTokenId = (String)accessToken;
        String refreshTokenId = (String)refreshToken;

        response = getMockMvc().perform(
            post("/oauth/token")
                .header(AUTHORIZATION, "Basic "+new String(Base64.encode((clientId+":"+SECRET).getBytes())))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                .param(REFRESH_TOKEN, refreshTokenId)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE))

            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {});
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
    public void test_saml_bearer_grant() throws Exception {
        String subdomain  = generator.generate().toLowerCase();
        //all our SAML defaults use :8080/uaa/ so we have to use that here too
        String host = subdomain + ".localhost";
        String fullPath = "/uaa/oauth/token/alias/"+subdomain+".cloudfoundry-saml-login";
        String origin = subdomain + ".cloudfoundry-saml-login";

        MockMvcUtils.IdentityZoneCreationResult zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(),null);

        //create an actual IDP, so we can fetch metadata
        String idpMetadata = MockMvcUtils.getIDPMetaData(getMockMvc(), subdomain);

        //create an IDP in the default zone
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(origin, zone.getIdentityZone().getId(), idpMetadata);
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getIdentityZone().getId());
        provider.setName(origin);
        provider.setOriginKey(origin);

        IdentityZoneHolder.set(zone.getIdentityZone());
        getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class).create(provider);
        IdentityZoneHolder.clear();

        String assertion = samlTestUtils.mockAssertionEncoded(subdomain + ".cloudfoundry-saml-login",
                                                              "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                                                              "Saml2BearerIntegrationUser",
                                                              "http://"+subdomain+".localhost:8080/uaa/oauth/token/alias/"+subdomain+".cloudfoundry-saml-login",
                                                              subdomain + ".cloudfoundry-saml-login"
        );

        //create client in default zone
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.none", "uaa.user,openid", GRANT_TYPE_SAML2_BEARER+",password", true, TEST_REDIRECT_URI, null, 600, zone.getIdentityZone());


        //String fullPath = "/uaa/oauth/token";
        MockHttpServletRequestBuilder post = post(fullPath)
            .with(new RequestPostProcessor() {
                @Override
                public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                    request.setServerPort(8080);
                    request.setRequestURI(fullPath);
                    request.setServerName(host);
                    return request;
                }
            })
            .contextPath("/uaa")
            .accept(APPLICATION_JSON)
            .header(HOST, host)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer")
            .param("client_id", clientId)
            .param("client_secret", "secret")
            .param("assertion",assertion);


        getMockMvc().perform(post)
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope").value("openid uaa.user"));

        getMockMvc().perform(post.param("scope","uaa.admin"))
            .andDo(print())
            .andExpect(status().isBadRequest());

    }

    @Test
    public void test_two_zone_saml_bearer_grant() throws Exception {
        String subdomain  = generator.generate().toLowerCase();
        //all our SAML defaults use :8080/uaa/ so we have to use that here too
        String spInvocationEndpoint = "/uaa/oauth/token/alias/cloudfoundry-saml-login";
        String idpOrigin = subdomain + ".cloudfoundry-saml-login";

        //create an zone - that zone will be our IDP
        MockMvcUtils.IdentityZoneCreationResult zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(),null);
        //create an actual IDP, so we can fetch metadata
        String spMetadata = MockMvcUtils.getSPMetadata(getMockMvc(), null);
        String idpMetadata = MockMvcUtils.getIDPMetaData(getMockMvc(), subdomain);

        //create an IDP in the default zone
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(idpOrigin, IdentityZone.getUaa().getId(), idpMetadata);
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setName(idpOrigin);
        provider.setOriginKey(idpOrigin);

        IdentityZoneHolder.clear();
        getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class).create(provider);
        IdentityZoneHolder.clear();

        String assertion = samlTestUtils.mockAssertionEncoded(subdomain + ".cloudfoundry-saml-login",
                                                              "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                                                              "Saml2BearerIntegrationUser",
                                                              "http://localhost:8080/uaa/oauth/token/alias/cloudfoundry-saml-login",
                                                              "cloudfoundry-saml-login"
        );

        //create client in default zone
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.none", "uaa.user,openid", GRANT_TYPE_SAML2_BEARER+",password", true, TEST_REDIRECT_URI, null, 600, null);


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
            .param("assertion",assertion);


        String json = getMockMvc().perform(post)
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").exists())
            .andExpect(jsonPath("$.scope").value("openid uaa.user"))
            .andReturn()
            .getResponse()
            .getContentAsString();

        System.out.println("json = " + json);

        getMockMvc().perform(post.param("scope","uaa.admin"))
            .andDo(print())
            .andExpect(status().isBadRequest());

    }

    @Test
    public void getOauthToken_Password_Grant_When_UAA_Provider_is_Disabled() throws Exception {
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "password", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));

        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        setDisableInternalAuth(getWebApplicationContext(), IdentityZone.getUaa().getId(), true);
        try {
            getMockMvc().perform(post("/oauth/token")
                                     .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                     .param(OAuth2Utils.RESPONSE_TYPE, "token")
                                     .param(OAuth2Utils.GRANT_TYPE, "password")
                                     .param(OAuth2Utils.CLIENT_ID, clientId)
                                     .param("client_secret", SECRET)
                                     .param("username", username)
                                     .param("password", SECRET))
                .andExpect(status().isUnauthorized());
        } finally {
            setDisableInternalAuth(getWebApplicationContext(), IdentityZone.getUaa().getId(), false);
        }
    }

    @Test
    public void token_endpoint_should_return_Basic_WWW_Authenticate_Header() throws Exception {
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "authorization_code", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        MockHttpSession session = getAuthenticatedSession(developer);
        String state = generator.generate();
        MvcResult result = getMockMvc().perform(get("/oauth/authorize")
                                                    .session(session)
                                                    .param(OAuth2Utils.RESPONSE_TYPE, "code")
                                                    .param(OAuth2Utils.STATE, state)
                                                    .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isFound())
            .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);

        assertThat(code.length(), greaterThan(9));

        state = ((List<String>) query.get("state")).get(0);

        getMockMvc().perform(post("/oauth/token")
                                 .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                 .accept(MediaType.APPLICATION_JSON_VALUE)
                                 .param(OAuth2Utils.RESPONSE_TYPE, "token")
                                 .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
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
    public void getOauthToken_usingAuthCode_withClientIdAndSecretInRequestBody_shouldBeOk() throws Exception {
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "authorization_code", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));

        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = getMockMvc().perform(get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId))
                .andExpect(status().isFound())
                .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);

        assertThat(code.length(), greaterThan(9));

        state = ((List<String>) query.get("state")).get(0);

        getMockMvc().perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", "secret")
                .param("code", code)
                .param("state", state))
                .andExpect(status().isOk());
    }

    protected MockHttpSession getAuthenticatedSession(ScimUser user) {
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, user);
        return session;
    }

    @Test
    public void testRefreshTokenNotPresentWhenClientDoesNotHaveGrantType() throws Exception {
        BaseClientDetails clientWithoutRefreshTokenGrant = setUpClients("testclient"+generator.generate(), "", "openid", "authorization_code", true);
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user,other.scope,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        MvcResult result = getMockMvc().perform(get("/oauth/authorize")
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.CLIENT_ID, clientWithoutRefreshTokenGrant.getClientId()))
            .andExpect(status().isFound())
            .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.CLIENT_ID, clientWithoutRefreshTokenGrant.getClientId())
            .param("client_secret", "secret")
            .param("code", code);

        MvcResult mvcResult = getMockMvc().perform(oauthTokenPost).andReturn();
        assertNotNull(JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), Map.class).get("access_token"));
        assertNull(JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), Map.class).get("refresh_token"));
    }

    @Test
    public void refreshAccessToken_withClient_withAutoApproveField() throws Exception {
        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Arrays.asList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Arrays.asList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = getMockMvc().perform(get("/oauth/authorize")
          .session(session)
          .param(OAuth2Utils.RESPONSE_TYPE, "code")
          .param(OAuth2Utils.STATE, state)
          .param(OAuth2Utils.CLIENT_ID, clientId))
          .andExpect(status().isFound())
          .andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        String code = ((List<String>) query.get("code")).get(0);
        state = ((List<String>) query.get("state")).get(0);

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
          .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
          .accept(MediaType.APPLICATION_JSON_VALUE)
          .param(OAuth2Utils.RESPONSE_TYPE, "token")
          .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
          .param(OAuth2Utils.CLIENT_ID, clientId)
          .param("client_secret", "secret")
          .param("code", code)
          .param("state", state);

        MvcResult mvcResult = getMockMvc().perform(oauthTokenPost).andReturn();
        OAuth2RefreshToken refreshToken = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), CompositeAccessToken.class).getRefreshToken();

        MockHttpServletRequestBuilder postForRefreshToken = post("/oauth/token")
          .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
          .param(GRANT_TYPE, REFRESH_TOKEN)
          .param(REFRESH_TOKEN, refreshToken.getValue());
        getMockMvc().perform(postForRefreshToken).andExpect(status().isOk());
    }

    @Test
    public void authorizeEndpointWithPromptNone_WhenNotAuthenticated() throws Exception {
        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Arrays.asList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Arrays.asList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        MockHttpSession session = new MockHttpSession();

        String state = generator.generate();

        MvcResult result = getMockMvc().perform(
            get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE))
            .andExpect(status().isFound())
            .andExpect(cookie().maxAge("Current-User", 0))
            .andReturn();

        String url = result.getResponse().getHeader("Location");
        assertEquals(UaaUrlUtils.addQueryParameter(TEST_REDIRECT_URI, "error", "login_required"), url);

    }

    @Test
    public void testAuthorizeEndpointWithPromptNone_Authenticated() throws Exception {
        String clientId = "testclient"+ generator.generate();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "uaa.user,other.scope", "authorization_code,refresh_token", "uaa.resource", TEST_REDIRECT_URI);
        clientDetails.setAutoApproveScopes(Arrays.asList("uaa.user"));
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.AUTO_APPROVE, Arrays.asList("other.scope"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList("uaa"));
        clientDetailsService.addClientDetails(clientDetails);

        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user,other.scope";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MvcResult result = getMockMvc().perform(get("/oauth/authorize")
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
    public void getOauthToken_usingPassword_withClientIdAndSecretInRequestBody_shouldBeOk() throws Exception {
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "password", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));

        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        getMockMvc().perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", SECRET)
                .param("username", username)
                .param("password", SECRET))
                .andExpect(status().isOk());
    }

    @Test
    public void getOauthToken_usingPassword_withNoCommonScopes_shouldBeUnauthorized() throws Exception {
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.user", "something_else", "password", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));

        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());

        MvcResult result = getMockMvc().perform(post("/oauth/token")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
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
    public void getOauthToken_usingClientCredentials_withClientIdAndSecretInRequestBody_shouldBeOk() throws Exception {
        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, "uaa.user", "uaa.user", "client_credentials", true, TEST_REDIRECT_URI, Arrays.asList("uaa"));

        getMockMvc().perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "client_credentials")
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk());
    }

    @Test
    public void testClientIdentityProviderWithoutAllowedProvidersForPasswordGrantWorksInOtherZone() throws Exception {
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        //a client without allowed providers in non default zone should always be rejected
        String subdomain = "testzone"+ generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider(OriginKeys.UAA);

        String clientId2 = "testclient"+ generator.generate();
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));

        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        String username = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, testZone.getId());

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isOk());

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId2 + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId2))
            .andExpect(status().isOk());


    }

    @Test
    public void getToken_withPasswordGrantType_resultsInUserLastLogonTimestampUpdate() throws Exception {
        String username = "testuser"+ generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());
        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());

        String accessToken = getAccessTokenForPasswordGrant(username);
        Long firstTimestamp = getPreviousLogonTime(accessToken);

        String accessToken2 = getAccessTokenForPasswordGrant(username);
        Long secondTimestamp = getPreviousLogonTime(accessToken2);

        assertNotEquals(firstTimestamp, secondTimestamp);
        assertTrue(firstTimestamp < secondTimestamp);
    }

    private String getAccessTokenForPasswordGrant(String username) throws Exception {
        String response = getMockMvc().perform(
            post("/oauth/token")
                .param("client_id", "cf")
                .param("client_secret", "")
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
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
        String userInfoResponse = getMockMvc().perform(
            get("/userinfo")
                .header("Authorization", "bearer " + accessToken)
                .accept(APPLICATION_JSON)
        ).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        assertNotNull(userInfoResponse);
        userInfo = JsonUtils.readValue(userInfoResponse, UserInfoResponse.class);
        return userInfo.getPreviousLogonSuccess();
    }

    @Test
    public void testClientIdentityProviderClientWithoutAllowedProvidersForAuthCodeAlreadyLoggedInWorksInAnotherZone() throws Exception {
        //a client without allowed providers in non default zone should always be rejected
        String subdomain = "testzone"+ generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider(OriginKeys.UAA);

        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        String clientId = "testclient"+ generator.generate();
        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        String clientId2 = "testclient"+ generator.generate();
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));

        String clientId3 = "testclient"+ generator.generate();
        setUpClients(clientId3, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(OriginKeys.LOGIN_SERVER));

        String username = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, testZone.getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        IdentityZoneHolder.clear();

        //no providers is ok
        getMockMvc().perform(get("/oauth/authorize")
            .session(session)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
            .andExpect(status().isFound());

        //correct provider is ok
        MvcResult result = getMockMvc().perform(get("/oauth/authorize")
            .session(session)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId2)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
            .andExpect(status().isFound())
            .andReturn();

        //other provider, not ok
        getMockMvc().perform(get("/oauth/authorize")
            .session(session)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId3)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
            .andExpect(status().isUnauthorized())
            .andExpect(model().attributeExists("error"))
            .andExpect(model().attribute("error_message_code","login.invalid_idp"));


        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);

    }

    @Test
    public void testClientIdentityProviderRestrictionForPasswordGrant() throws Exception {
        //a client with allowed providers in the default zone should be rejected if the client is not allowed
        String clientId = "testclient"+ generator.generate();
        String clientId2 = "testclient"+ generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";

        String idpOrigin = "origin-"+ generator.generate();
        IdentityProvider provider = setupIdentityProvider(idpOrigin);

        setUpClients(clientId, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));
        setUpClients(clientId2, scopes, scopes, "authorization_code,password", true, TEST_REDIRECT_URI, null);

        //create a user in the UAA identity provider
        String username = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());


        getMockMvc().perform(post("/oauth/token")
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isUnauthorized());

        getMockMvc().perform(post("/oauth/token")
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId2 + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId2))
            .andExpect(status().isOk());
    }

    @Test
    public void test_Oauth_Authorize_API_Endpoint() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "openid,uaa.user,scim.me";
        setUpClients(clientId, "", scopes, "authorization_code,refresh_token", true);
        String username = "testuser"+ generator.generate();
        String userScopes = "";
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        String cfAccessToken = getUserOAuthAccessToken(
            getMockMvc(),
            "cf",
            "",
            username,
            SECRET,
            ""
        );

        String state = generator.generate();

        MockHttpServletRequestBuilder oauthAuthorizeGet = get("/oauth/authorize")
            .header("Authorization", "Bearer " + cfAccessToken)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId);

        MvcResult result = getMockMvc().perform(oauthAuthorizeGet).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        assertNotNull("Location must be present", location);
        assertThat("Location must have a code parameter.", location, containsString("code="));
        URL url = new URL(location);
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);

        String body = getMockMvc().perform(post("/oauth/token")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .accept(APPLICATION_JSON)
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param("code", code))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        assertNotNull("Token body must not be null.", body);
        assertThat(body, stringContainsInOrder(Arrays.asList(ACCESS_TOKEN, REFRESH_TOKEN)));
        Map<String,Object> map = JsonUtils.readValue(body, new TypeReference<Map<String,Object>>() {});
        String accessToken = (String) map.get("access_token");
        OAuth2Authentication token = tokenServices.loadAuthentication(accessToken);
        assertTrue("Must have uaa.user scope", token.getOAuth2Request().getScope().contains("uaa.user"));
    }

    @Test
    public void refreshTokenIssued_whenScopeIsPresent_andRestrictedOnGrantType() throws Exception {
        UaaTokenServices bean = getWebApplicationContext().getBean(UaaTokenServices.class);
        bean.setRestrictRefreshGrant(true);
        String clientId = "testclient"+ generator.generate();
        String scopes = "openid,uaa.user,scim.me,"+ UaaTokenServices.UAA_REFRESH_TOKEN;
        setUpClients(clientId, "", scopes, "password,refresh_token", true);

        String username = "testuser"+ generator.generate();
        String userScopes = UaaTokenServices.UAA_REFRESH_TOKEN;
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .param("username", username)
            .param("password", SECRET)
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password");
        MvcResult result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get("access_token"));
        assertNotNull(token.get(REFRESH_TOKEN));
        bean.setRestrictRefreshGrant(false);
    }

    @Test
    public void refreshAccessToken_whenScopeIsPresent_andRestrictedOnGrantType() throws Exception {
        UaaTokenServices bean = getWebApplicationContext().getBean(UaaTokenServices.class);
        bean.setRestrictRefreshGrant(true);
        String clientId = "testclient"+ generator.generate();
        String scopes = "openid,uaa.user,scim.me,"+ UaaTokenServices.UAA_REFRESH_TOKEN;
        setUpClients(clientId, "", scopes, "password,refresh_token", true);

        String username = "testuser"+ generator.generate();
        String userScopes = UaaTokenServices.UAA_REFRESH_TOKEN;
        setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .param("username", username)
            .param("password", SECRET)
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password");
        MvcResult mvcResult = getMockMvc().perform(oauthTokenPost).andReturn();
        OAuth2RefreshToken refreshToken = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), CompositeAccessToken.class).getRefreshToken();

        MockHttpServletRequestBuilder postForRefreshToken = post("/oauth/token")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(GRANT_TYPE, REFRESH_TOKEN)
            .param(REFRESH_TOKEN, refreshToken.getValue());
        getMockMvc().perform(postForRefreshToken).andExpect(status().isOk());


        getMockMvc().perform(postForRefreshToken.param(REQUEST_TOKEN_FORMAT, OPAQUE)).andExpect(status().isOk());
        getMockMvc().perform(postForRefreshToken.param(REQUEST_TOKEN_FORMAT, OPAQUE)).andExpect(status().isOk());
        bean.setRestrictRefreshGrant(false);
    }

    @Test
    public void testOpenIdTokenHybridFlowWithNoImplicitGrant_When_IdToken_Disabled() throws Exception {
        try {
            getWebApplicationContext().getBean(DisableIdTokenResponseTypeFilter.class).setIdTokenDisabled(true);

            String clientId = "testclient" + generator.generate();
            String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
            setUpClients(clientId, scopes, scopes, "authorization_code", true);
            String username = "testuser" + generator.generate();
            String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
            ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

            MockHttpSession session = getAuthenticatedSession(developer);

            String state = generator.generate();

            MockHttpServletRequestBuilder oauthTokenPost = get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

            MvcResult result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
            String location = result.getResponse().getHeader("Location");
            assertFalse(location.contains("#"));
            URL url = new URL(location);
            Map query = splitQuery(url);
            assertNotNull(query.get("code"));
            assertNull(query.get("id_token"));
            String code = ((List<String>) query.get("code")).get(0);
            assertNotNull(code);
        }finally {
            getWebApplicationContext().getBean(DisableIdTokenResponseTypeFilter.class).setIdTokenDisabled(false);
        }
    }

    @Test
    public void testOpenIdTokenHybridFlowWithNoImplicitGrant() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", true);
        String username = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        MockHttpServletRequestBuilder oauthTokenPost = get("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
                .param(SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        assertTrue(location.contains("#"));
        URL url = new URL(location.replace("redirect#", "redirect?"));
        Map query = splitQuery(url);
        assertNotNull(((List)query.get("id_token")).get(0));
        assertNotNull(((List)query.get("code")).get(0));
        assertNull(query.get("token"));
    }

    @Test
    public void prompt_is_none_and_approvals_are_required() throws Exception {
        String redirectUrl = TEST_REDIRECT_URI + "#test=true";
        String clientId = "testclient" + new RandomValueStringGenerator().generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "implicit,authorization_code", false);
        String username = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = new RandomValueStringGenerator().generate();

        getMockMvc().perform(
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
    public void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenLenientWhenAppNotApproved() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", false);
        String username = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setClientId(clientId);
        authorizationRequest.setRedirectUri(TEST_REDIRECT_URI);
        authorizationRequest.setScope(new ArrayList<>(Arrays.asList("openid")));
        authorizationRequest.setResponseTypes(new TreeSet<>(Arrays.asList("code","id_token")));
        authorizationRequest.setState(state);

        session.setAttribute("authorizationRequest", authorizationRequest);

        MvcResult result  = getMockMvc().perform(
            post("/oauth/authorize")
                .session(session)
                .with(cookieCsrf())
                .param(OAuth2Utils.USER_OAUTH_APPROVAL, "true")
                .param("scope.0","openid")
        ).andExpect(status().is3xxRedirection()).andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("code"));
        String code = ((List<String>) query.get("code")).get(0);
        assertNotNull(code);
    }

    @Test
    public void testOpenIdTokenHybridFlowWithNoImplicitGrantWhenStrictWhenAppNotApproved() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", false);
        String username = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();

        AuthorizationRequest authorizationRequest = new AuthorizationRequest();
        authorizationRequest.setClientId(clientId);
        authorizationRequest.setRedirectUri(TEST_REDIRECT_URI);
        authorizationRequest.setScope(new ArrayList<>(Arrays.asList("openid")));
        authorizationRequest.setResponseTypes(new TreeSet<>(Arrays.asList("code", "id_token")));
        authorizationRequest.setState(state);
        session.setAttribute("authorizationRequest", authorizationRequest);

        MvcResult result  = getMockMvc().perform(
            post("/oauth/authorize")
                .session(session)
                .param(OAuth2Utils.USER_OAUTH_APPROVAL, "true")
                .with(cookieCsrf())
                .param("scope.0", "openid")
        ).andExpect(status().is3xxRedirection()).andReturn();

        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        Map query = splitQuery(url);
        assertNotNull(query.get("id_token"));
        assertNotNull(((List)query.get("id_token")).get(0));
        assertNotNull(((List) query.get("code")).get(0));
        assertNull(query.get("token"));
    }

    @Test
    public void test_subdomain_redirect_url() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";
        String subDomainUri = redirectUri.replace("example.com", "test.example.com");
        String clientId = "authclient-"+ generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser"+ generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));
        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, subDomainUri);

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        location = location.substring(0,location.indexOf("&code="));
        assertEquals(subDomainUri, location);
    }

    @Test
    public void invalidScopeErrorMessageIsNotShowingAllClientScopes() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, "authorization_code", true);

        String username = "testuser"+ generator.generate();
        ScimUser developer = setUpUser(username, "scim.write", OriginKeys.UAA, IdentityZoneHolder.getUaaZone().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "scim.write")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult mvcResult = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();

        UriComponents locationComponents = UriComponentsBuilder.fromUri(URI.create(mvcResult.getResponse().getHeader("Location"))).build();
        MultiValueMap<String, String> queryParams = locationComponents.getQueryParams();
        String errorMessage = URIUtil.encodeQuery("scim.write is invalid. Please use a valid scope name in the request");
        assertTrue(!queryParams.containsKey("scope"));
        assertEquals(errorMessage, queryParams.getFirst("error_description"));
    }

    @Test
    public void invalidScopeErrorMessageIsNotShowingAllUserScopes() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "openid,password.write,cloud_controller.read,scim.userids,password.write,something.else";
        setUpClients(clientId, scopes, scopes, "authorization_code", true);

        String username = "testuser"+ generator.generate();
        ScimUser developer = setUpUser(username, "openid", OriginKeys.UAA, IdentityZoneHolder.getUaaZone().getId());
        MockHttpSession session = getAuthenticatedSession(developer);

        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "something.else")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        MvcResult mvcResult = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();

        UriComponents locationComponents = UriComponentsBuilder.fromUri(URI.create(mvcResult.getResponse().getHeader("Location"))).build();
        MultiValueMap<String, String> queryParams = locationComponents.getQueryParams();
        String errorMessage = URIUtil.encodeQuery("[something.else] is invalid. This user is not allowed any of the requested scopes");
        assertTrue(!queryParams.containsKey("scope"));
        assertEquals(errorMessage, queryParams.getFirst("error_description"));
    }

    @Test
    public void ensure_that_form_redirect_is_not_a_parameter_unless_there_is_a_saved_request() throws Exception {
        //make sure we don't create a session on the homepage
        assertNull(
            getMockMvc().perform(
                get("/login")
            )
                .andDo(print())
                .andExpect(content().string(not(containsString(FORM_REDIRECT_PARAMETER))))
                .andReturn().getRequest().getSession(false));

        //if there is a session, but no saved request
        getMockMvc().perform(
            get("/login")
            .session(new MockHttpSession())
        )
            .andDo(print())
            .andExpect(content().string(not(containsString(FORM_REDIRECT_PARAMETER))));
    }

    public void setAuthentication(MockHttpSession session, ScimUser developer) {
        UaaPrincipal p = new UaaPrincipal(developer.getId(),developer.getUserName(),developer.getPrimaryEmail(), OriginKeys.UAA,"", IdentityZoneHolder.get().getId());
        UaaAuthentication auth = new UaaAuthentication(p, UaaAuthority.USER_AUTHORITIES, new UaaAuthenticationDetails(false, "clientId", OriginKeys.ORIGIN,"sessionId"));
        Assert.assertTrue(auth.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(auth);
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(auth)
        );
    }

    @Test
    public void test_authorization_code_grant_session_expires_during_app_approval() throws Exception {
        String username = "authuser"+ generator.generate();
        ScimUser user = setUpUser(username, "", OriginKeys.UAA, IdentityZoneHolder.get().getId());

        String redirectUri = "http://localhost:8080/app/";
        String clientId = "authclient-"+ generator.generate();
        String scopes = "openid,password.write,cloud_controller.read,scim.userids,password.write";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, false, redirectUri);


        String state = generator.generate();

        String url = UriComponentsBuilder
            .fromUriString("/oauth/authorize?response_type=code&scope=openid&state={state}&client_id={clientId}&redirect_uri={redirectUri}")
            .buildAndExpand(state,clientId,redirectUri)
            .encode()
            .toUri()
            .toString();

        MockHttpSession session = getAuthenticatedSession(user);

        MvcResult result = getMockMvc()
            .perform(get(new URI(url))
            .session(session))
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(forwardedUrl("/oauth/confirm_access"))
            .andExpect(model().attribute("original_uri", "http://localhost"+url))
            .andReturn();
    }

    @Test
    public void test_authorization_code_grant_redirect_when_session_expires() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";

        String clientId = "authclient-"+ generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser"+ generator.generate();
        String userScopes = "openid";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String state = generator.generate();

        String url = UriComponentsBuilder
            .fromUriString("/oauth/authorize?response_type=code&scope=openid&state={state}&client_id={clientId}&redirect_uri={redirectUri}")
            .buildAndExpand(state,clientId,redirectUri)
            .encode()
            .toUri()
            .toString();

        String encodedRedirectUri = UriUtils.encodeQueryParam(redirectUri, "ISO-8859-1");

        MvcResult result = getMockMvc()
            .perform(get(new URI(url)))
            .andExpect(status().is3xxRedirection())
            .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location, endsWith("/login"));

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session);
        SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        assertNotNull(savedRequest);
        assertEquals("http://localhost"+url, savedRequest.getRedirectUrl());

        getMockMvc().perform(
            get("/login")
            .session(session)
        )
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(FORM_REDIRECT_PARAMETER)))
            .andExpect(content().string(containsString(encodedRedirectUri)));

        //a failed login should survive the flow
        //attempt to login without a session
        result = getMockMvc().perform(
            post("/login.do")
                .with(cookieCsrf())
                .param("form_redirect_uri", url)
                .param("username", username)
                .param("password", "invalid")
        )
            .andExpect(status().isFound())
            .andExpect(header().string("Location", containsString("/login")))
            .andReturn();

        session = (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session);
        savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        assertNotNull(savedRequest);

        getMockMvc().perform(
            get("/login")
                .session(session)
        )
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(FORM_REDIRECT_PARAMETER)))
            .andExpect(content().string(containsString(encodedRedirectUri)));

        //attempt to login without a session
        getMockMvc().perform(
            post("/login.do")
                .with(cookieCsrf())
                .param("form_redirect_uri", url)
                .param("username", username)
                .param("password", SECRET)
        )
            .andExpect(status().isFound())
            .andExpect(header().string("Location", url));
    }

    @Test
    public void test_missing_redirect_uri() throws Exception {

        test_invalid_registered_redirect_uris(emptySet(), status().isBadRequest());
    }

    @Test
    public void test_invalid_redirect_uri() throws Exception {
        test_invalid_registered_redirect_uris(new HashSet(Arrays.asList("*","*/*")), status().isBadRequest());
    }

    @Test
    public void test_valid_redirect_uri() throws Exception {
        String redirectUri = "https://example.com/**";
        test_invalid_registered_redirect_uris(new HashSet(Arrays.asList(redirectUri)), status().isFound());
    }


    public void test_invalid_registered_redirect_uris(Set<String> redirectUris, ResultMatcher resultMatcher) throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";
        String clientId = "authclient-"+ generator.generate();
        String scopes = "openid";
        BaseClientDetails client = setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        client.setRegisteredRedirectUri(redirectUris);
        getWebApplicationContext().getBean(ClientServicesExtension.class).updateClientDetails(client);

        String username = "authuser"+ generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));
        MockHttpSession session = getAuthenticatedSession(developer);


        String state = generator.generate();

        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        getMockMvc().perform(authRequest).andExpect(resultMatcher);
    }

    @Test
    public void testAuthorizationCodeGrantWithEncodedRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=%7B%22orgGuid%22%3A%22org-guid%22%2C%22spaceGuid%22%3A%22space-guid%22%2C%22appGuid%22%3A%22app-guid%22%2C%22redirect%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D";
        //String redirectUri = "https://example.com/dashboard/?appGuid=app-guid&ace_config=test";
        String clientId = "authclient-"+ generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser"+ generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));
        MockHttpSession session = getAuthenticatedSession(developer);

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        location = location.substring(0,location.indexOf("&code="));
        assertEquals(redirectUri, location);
    }

    @Test
    public void make_sure_Bootstrapped_users_Dont_Revoke_Tokens_If_No_Change() throws Exception {
        String tokenString = getMockMvc().perform(post("/oauth/token")
            .param("username", "testbootuser")
            .param("password", "password")
            .header("Authorization", "Basic " + new String(Base64.encode(("cf:").getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, "cf")
        )
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> tokenResponse = JsonUtils.readValue(tokenString, new TypeReference<Map<String, Object>>() {
        });
        String accessToken = (String)tokenResponse.get("access_token");

        //ensure we can do scim.read
        getMockMvc().perform(get("/Users")
            .header("Authorization", "Bearer "+accessToken)
            .accept(APPLICATION_JSON)
        ).andExpect(status().isOk());

        ScimUserBootstrap bootstrap = getWebApplicationContext().getBean(ScimUserBootstrap.class);
        boolean isOverride = bootstrap.isOverride();
        bootstrap.setOverride(true);
        bootstrap.afterPropertiesSet();
        bootstrap.setOverride(isOverride);

        //ensure we can do scim.read with the existing token
        getMockMvc().perform(get("/Users")
                .header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON)
        ).andExpect(status().isOk());

    }

    @Test
    public void testAuthorizationCode_ShouldNot_Throw_500_If_Client_Doesnt_Exist() throws Exception {
        String redirectUri = "https://example.com/";
        String clientId = "nonexistent-"+ generator.generate();
        String userScopes = "openid";

        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .accept(MediaType.TEXT_HTML)
            .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
            .param(SCOPE, userScopes)
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");

        HttpSession session = result.getRequest().getSession(false);

        MockHttpServletRequestBuilder login = get("/login")
            .accept(MediaType.TEXT_HTML)
            .session((MockHttpSession) session);
        getMockMvc().perform(login).andExpect(status().isOk());
    }

    @Test
    public void testImplicitGrantWithFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid#test";
        testImplicitGrantRedirectUri(redirectUri, false);
    }

    @Test
    public void testImplicitGrantWithNoFragmentInRedirectURL() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        testImplicitGrantRedirectUri(redirectUri, false);
    }

    @Test
    public void testImplicitGrantWithFragmentInRedirectURLAndNoPrompt() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid#test";
        testImplicitGrantRedirectUri(redirectUri, true);
    }

    @Test
    public void testImplicitGrantWithNoFragmentInRedirectURLAndNoPrompt() throws Exception {
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        testImplicitGrantRedirectUri(redirectUri, true);
    }

    @Test
    public void testWildcardRedirectURL() throws Exception {
        String state = generator.generate();
        String clientId = "authclient-"+ generator.generate();
        String scopes = "openid";
        String redirectUri = "http*://subdomain.domain.com/**/path2?query1=value1";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser"+ generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));
        MockHttpSession session = getAuthenticatedSession(developer);


        String requestedUri = "https://subdomain.domain.com/path1/path2?query1=value1";
        ResultMatcher status = status().is3xxRedirection();
        performAuthorize(state, clientId, basicDigestHeaderValue, session, requestedUri, status);

        requestedUri = "http://subdomain.domain.com/path1/path2?query1=value1";
        performAuthorize(state, clientId, basicDigestHeaderValue, session, requestedUri, status);

        requestedUri = "http://subdomain.domain.com/path1/path1a/path1b/path2?query1=value1";
        performAuthorize(state, clientId, basicDigestHeaderValue, session, requestedUri, status);

        requestedUri = "https://wrongsub.domain.com/path1/path2?query1=value1";
        status = status().is4xxClientError();
        performAuthorize(state, clientId, basicDigestHeaderValue, session, requestedUri, status);

        requestedUri = "https://subdomain.domain.com/path1/path2?query1=value1&query2=value2";
        status = status().is4xxClientError();
        performAuthorize(state, clientId, basicDigestHeaderValue, session, requestedUri, status);


    }

    protected void performAuthorize(String state, String clientId, String basicDigestHeaderValue, MockHttpSession session, String requestedUri, ResultMatcher status) throws Exception {
        getMockMvc().perform(
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

    protected void testImplicitGrantRedirectUri(String redirectUri, boolean noPrompt) throws Exception {
        String clientId = "authclient-"+ generator.generate();
        String scopes = "openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, redirectUri);
        String username = "authuser"+ generator.generate();
        String userScopes = "openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));
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

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");

        constainsExactlyOneInstance(location, "#");
        String[] locationParts = location.split("#");

        String locationUri = locationParts[0];
        String locationToken = locationParts[1];

        assertEquals(redirectUri.split("#")[0], locationUri);
        String[] locationParams = locationToken.split("&");
        assertThat(Arrays.asList(locationParams), hasItem(is("token_type=bearer")));
        assertThat(Arrays.asList(locationParams), hasItem(startsWith("access_token=")));
    }

    private static void constainsExactlyOneInstance(String string, String substring) {
        assertTrue(string.contains(substring));
        assertEquals(string.indexOf(substring), string.lastIndexOf(substring));
    }

    @Test
    public void testOpenIdToken() throws Exception {
        RandomValueStringGenerator generator = this.generator;
        String clientId = "testclient"+ generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,openid";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String username = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three,openid";
        ScimUser developer = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(developer.getId());
        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(developer.getId());
        String authCodeClientId = "testclient"+ generator.generate();
        setUpClients(authCodeClientId, scopes, scopes, "authorization_code,refresh_token", true);

        String implicitClientId = "testclient"+ generator.generate();
        setUpClients(implicitClientId, scopes, scopes, "implicit", true);

        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((clientId + ":" + SECRET).getBytes()));

        String authCodeBasicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64((authCodeClientId + ":" + SECRET).getBytes()));

        //password grant - request for id_token
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param(OAuth2Utils.RESPONSE_TYPE,"token id_token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param("username", username)
            .param("password", SECRET)
            .param(SCOPE, "openid");
        MvcResult result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        Map token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get("access_token"));
        assertNotNull(token.get(REFRESH_TOKEN));
        assertNotNull(token.get("id_token"));
        assertNotEquals(token.get("access_token"), token.get("id_token"));
        validateOpenIdConnectToken((String)token.get("id_token"), developer.getId(), clientId);

        //request for id_token using our old-style direct authentication
        //this returns a redirect with a fragment in the URL/Location header
        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", username, SECRET);
        oauthTokenPost = post("/oauth/authorize")
            .header("Accept", "application/json")
            .param(OAuth2Utils.RESPONSE_TYPE, "token id_token")
            .param(OAuth2Utils.CLIENT_ID, implicitClientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
            .param("credentials", credentials)
            .param(OAuth2Utils.STATE, generator.generate())
            .param(SCOPE, "openid");
        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        URL url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(((List<String>)token.get("access_token")).get(0));
        assertNotNull(((List<String>)token.get("id_token")).get(0));
        assertNotEquals(((List<String>) token.get("access_token")).get(0), ((List<String>) token.get("id_token")).get(0));
        validateOpenIdConnectToken(((List<String>)token.get("id_token")).get(0), developer.getId(), implicitClientId);

        //authorization_code grant - requesting id_token
        MockHttpSession session = new MockHttpSession();
        setAuthentication(session, developer);

        String state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, authCodeClientId)
            .param(ClaimConstants.NONCE, "testnonce")
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        String code = ((List<String>) token.get("code")).get(0);

        oauthTokenPost = post("/oauth/token")
            .header("Authorization", authCodeBasicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param("code", code)
            .param(OAuth2Utils.RESPONSE_TYPE, "token id_token")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, authCodeClientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);
        result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull(token.get("access_token"));
        assertNotNull(token.get(REFRESH_TOKEN));
        assertNotNull(token.get("id_token"));
        assertNotEquals(token.get("access_token"), token.get("id_token"));
        validateOpenIdConnectToken((String) token.get("id_token"), developer.getId(), authCodeClientId);

        //nonce must be in id_token if was in auth request, see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        Map<String,Object> claims = getClaimsForToken((String) token.get("id_token"));
        assertEquals("testnonce", claims.get(ClaimConstants.NONCE));

        //hybrid flow defined in - response_types=code token id_token
        //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        session = new MockHttpSession();
        setAuthentication(session, developer);

        state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code id_token token")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(((List<String>)token.get("access_token")).get(0));
        assertNotNull(((List<String>)token.get("id_token")).get(0));
        assertNotEquals(((List<String>) token.get("access_token")).get(0), ((List<String>) token.get("id_token")).get(0));
        validateOpenIdConnectToken(((List<String>)token.get("id_token")).get(0), developer.getId(), clientId);

        //hybrid flow defined in - response_types=code token
        //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        session = new MockHttpSession();
        setAuthentication(session, developer);

        state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code token")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(((List<String>)token.get("access_token")).get(0));

        //hybrid flow defined in - response_types=code id_token
        //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        session = new MockHttpSession();
        setAuthentication(session, developer);

        state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code id_token")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, authCodeClientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(token.get("code"));
        assertNotNull(((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        assertNotNull(((List<String>)token.get("id_token")).get(0));
        assertNull(((List<String>) token.get("token")));
        validateOpenIdConnectToken(((List<String>)token.get("id_token")).get(0), developer.getId(), authCodeClientId);

        //authorization code flow with parameter scope=openid
        //http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        session = new MockHttpSession();
        setAuthentication(session, developer);

        state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        assertFalse("Redirect URL should not be a fragment.",result.getResponse().getHeader("Location").contains("#"));
        url = new URL(result.getResponse().getHeader("Location"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        code = ((List<String>) token.get("code")).get(0);
        assertNotNull(code);

        oauthTokenPost = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .header("Authorization", basicDigestHeaderValue)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
            .param("code", code);
        result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull("ID Token should be present when scope=openid", token.get("id_token"));
        assertNotNull(token.get("id_token"));
        validateOpenIdConnectToken((String)token.get("id_token"), developer.getId(), clientId);

        //authorization code flow without parameter scope=openid
        //http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        //this behavior should NOT return an id_token
        session = new MockHttpSession();
        setAuthentication(session, developer);

        state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        assertFalse("Redirect URL should not be a fragment.",result.getResponse().getHeader("Location").contains("#"));
        url = new URL(result.getResponse().getHeader("Location"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        code = ((List<String>) token.get("code")).get(0);
        assertNotNull(code);

        oauthTokenPost = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .header("Authorization", basicDigestHeaderValue)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
            .param("code", code);
        result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNull("ID Token should not be present when scope=openid is not present", token.get("id_token"));


        //test if we can retrieve an ID token using
        //response type token+id_token after a regular auth_code flow
        session = new MockHttpSession();
        setAuthentication(session, developer);

        state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
        code = ((List<String>) token.get("code")).get(0);
        assertNotNull(code);

        oauthTokenPost = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .header("Authorization", basicDigestHeaderValue)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.RESPONSE_TYPE, "token id_token")
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI)
            .param("code", code);
        result = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        token = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        assertNotNull("ID Token should be present when response_type includes id_token", token.get("id_token"));
        assertNotNull(token.get("id_token"));
        assertNotNull(token.get("access_token"));
        validateOpenIdConnectToken((String)token.get("id_token"), developer.getId(), clientId);

        session = new MockHttpSession();
        setAuthentication(session, developer);

        state = generator.generate();
        oauthTokenPost = get("/oauth/authorize")
            .session(session)
            .param(OAuth2Utils.RESPONSE_TYPE, "id_token")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, implicitClientId)
            .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI);

        result = getMockMvc().perform(oauthTokenPost).andExpect(status().is3xxRedirection()).andReturn();
        url = new URL(result.getResponse().getHeader("Location").replace("redirect#","redirect?"));
        token = splitQuery(url);
        assertNotNull(token.get(OAuth2Utils.STATE));
        assertNotNull(token.get("id_token"));
        assertEquals(state, ((List<String>) token.get(OAuth2Utils.STATE)).get(0));
    }

    private void validateOpenIdConnectToken(String token, String userId, String clientId) throws Exception {
        Map<String,Object> result = getClaimsForToken(token);
        String iss = (String)result.get(ClaimConstants.ISS);
        assertEquals(tokenServices.getTokenEndpoint(), iss);
        String sub = (String)result.get(ClaimConstants.SUB);
        assertEquals(userId, sub);
        List<String> aud = (List<String>)result.get(ClaimConstants.AUD);
        assertTrue(aud.contains(clientId));
        Integer exp = (Integer)result.get(ClaimConstants.EXP);
        assertNotNull(exp);
        Integer iat = (Integer)result.get(ClaimConstants.IAT);
        assertNotNull(iat);
        assertTrue(exp>iat);
        List<String> openid = (List<String>)result.get(ClaimConstants.SCOPE);
        Assert.assertThat(openid, containsInAnyOrder("openid"));

        //TODO OpenID
        Integer auth_time = (Integer)result.get(ClaimConstants.AUTH_TIME);
        assertNotNull(auth_time);
        Long previous_logon_time = (Long) result.get(ClaimConstants.PREVIOUS_LOGON_TIME);
        assertNotNull(previous_logon_time);
        Long dbPreviousLogonTime = getWebApplicationContext().getBean(UaaUserDatabase.class).retrieveUserById(userId).getPreviousLogonTime();
        assertEquals(dbPreviousLogonTime, previous_logon_time);

    }

    private Map<String, Object> getClaimsForToken(String token) {
        Jwt tokenJwt;
        try {
            tokenJwt = JwtHelper.decode(token);
        } catch (Throwable t) {
            throw new InvalidTokenException("Invalid token (could not decode): " + token);
        }

        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read token claims", e);
        }

        String kid = tokenJwt.getHeader().getKid();
        assertNotNull("Token should have a key ID.", kid);
        tokenJwt.verifySignature(KeyInfo.getKey(kid).getVerifier());

        return claims;
    }

    public static Map<String, List<String>> splitQuery(URL url) throws UnsupportedEncodingException {
        Map<String, List<String>> params = new LinkedHashMap<>();
        String[] kv = url.getQuery().split("&");
        for (String pair : kv) {
            int i = pair.indexOf("=");
            String key = i > 0 ? URLDecoder.decode(pair.substring(0, i), "UTF-8") : pair;
            if (!params.containsKey(key)) {
                params.put(key, new LinkedList<String>());
            }
            String value = i > 0 && pair.length() > i + 1 ? URLDecoder.decode(pair.substring(i + 1), "UTF-8") : null;
            params.get(key).add(value);
        }
        return params;
    }


    @Test
    public void test_Token_Expiry_Time() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true,null,null,60*60*24*3650);
        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        Set<String> allUserScopes = new HashSet<>();
        allUserScopes.addAll(defaultAuthorities);
        allUserScopes.addAll(StringUtils.commaDelimitedListToSet(userScopes));

        String token = validatePasswordGrantToken(
            clientId,
            userId,
            "",
            allUserScopes.toArray(new String[0])
        );

        if (token.length()<=36) {
            token = getWebApplicationContext().getBean(JdbcRevocableTokenProvisioning.class).retrieve(token).getValue();
        }

        Jwt tokenJwt = JwtHelper.decode(token);

        Map<String, Object> claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        Integer expirationTime = (Integer)claims.get(ClaimConstants.EXP);

        Calendar nineYearsAhead = new GregorianCalendar();
        nineYearsAhead.setTimeInMillis(System.currentTimeMillis());
        nineYearsAhead.add(Calendar.YEAR, 9);
        assertTrue("Expiration Date should be more than 9 years ahead.", new Date(expirationTime*1000l).after(new Date(nineYearsAhead.getTimeInMillis())));


    }

    @Test
    public void required_user_groups_password_grant() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "*.*";
        Map<String, Object> additional = new HashMap();
        additional.put(ClientConstants.REQUIRED_USER_GROUPS, Arrays.asList("non.existent"));
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true, null, null, -1, null, additional);
        String userId = "testuser"+ generator.generate();
        String userScopes = "scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());

        getMockMvc().perform(
            post("/oauth/token")
                .param("client_id", clientId)
                .param("client_secret", SECRET)
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("username", developer.getUserName())
                .param("password", SECRET)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_scope"))
            .andExpect(jsonPath("$.error_description").value("User does not meet the client's required group criteria."))
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"));
    }

    @Test
    public void testWildcardPasswordGrant() throws Exception {
        String clientId = "testclient"+ generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String userId = "testuser"+ generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        Set<String> allUserScopes = new HashSet<>();
        allUserScopes.addAll(defaultAuthorities);
        allUserScopes.addAll(StringUtils.commaDelimitedListToSet(userScopes));

        validatePasswordGrantToken(
            clientId,
            userId,
            "",
            allUserScopes.toArray(new String[0])
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "space.*.developer",
            "space.1.developer",
            "space.2.developer"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "space.2.developer",
            "space.2.developer"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin",
            "org.12345.admin"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin,space.1.developer",
            "org.12345.admin",
            "space.1.developer"
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin,space.*.developer",
            "org.12345.admin",
            "space.1.developer",
            "space.2.developer"
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
            "org.123*.admin,space.*.developer,*.*",
            set1.toArray(new String[0])
        );
        validatePasswordGrantToken(
            clientId,
            userId,
            "org.123*.admin,space.*.developer,scope.*",
            "org.12345.admin",
            "space.1.developer",
            "space.2.developer",
            "scope.one",
            "scope.two",
            "scope.three"
        );


    }

    public String validatePasswordGrantToken(String clientId, String username, String requestedScopes, String... expectedScopes) throws Exception {
        String t1 = testClient.getUserOAuthAccessToken(clientId, SECRET, username, SECRET, requestedScopes);
        OAuth2Authentication a1 = tokenServices.loadAuthentication(t1);
        assertEquals(expectedScopes.length, a1.getOAuth2Request().getScope().size());
        assertThat(
            a1.getOAuth2Request().getScope(),
            containsInAnyOrder(expectedScopes)
        );
        return t1;
    }

    @Test
    public void testLoginAddNewUserForOauthTokenPasswordGrant() throws Exception {
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
        getMockMvc().perform(post("/oauth/token")
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
        UaaUserDatabase db = getWebApplicationContext().getBean(UaaUserDatabase.class);
        UaaUser user = db.retrieveUserByName(username, OriginKeys.LOGIN_SERVER);
        assertNotNull(user);
        assertEquals(username, user.getUsername());
        assertEquals(email, user.getEmail());
        assertEquals(first, user.getGivenName());
        assertEquals(last, user.getFamilyName());
    }

    @Test
    public void testLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes, OriginKeys.LOGIN_SERVER, IdentityZoneHolder.get().getId());
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");

        //the login server is matched by providing
        //1. Bearer token (will be authenticated for oauth.login scope)
        //2. source=login
        //3. grant_type=password
        //4. add_new=<any value>
        //without the above four parameters, it is not considered a external login-server request

        //success - contains everything we need
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isUnauthorized());

        //failure - invalid client ID
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("user_id", developer.getId())
            .param(OriginKeys.ORIGIN, developer.getOrigin()))
            .andExpect(status().isUnauthorized());

        //failure - add_new is missing, so missing user password should trigger a failure
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
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
    public void testOtherOauthResourceLoginAuthenticationFilter() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);


        String oauthClientId = "testclient" + generator.generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES, true);


        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(oauthClientId, SECRET, "");

        //failure - success only if token has oauth.login
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("source", "login")
            .param("add_new", "false")
            .param("grant_type", "password")
            .param("client_secret", SECRET)
            .param("user_id", developer.getId()))
            .andExpect(status().isForbidden());

        //failure - invalid client ID
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
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
    public void testOtherClientAuthenticationMethods() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String oauthClientId = "testclient" + generator.generate();
        String oauthScopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*,oauth.something";
        setUpClients(oauthClientId, oauthScopes, oauthScopes, GRANT_TYPES, true);

        String userId = "testuser" + generator.generate();
        String userScopes = "space.1.developer,space.2.developer,org.1.reader,org.2.reader,org.12345.admin,scope.one,scope.two,scope.three";
        ScimUser developer = setUpUser(userId, userScopes, OriginKeys.UAA, IdentityZoneHolder.get().getId());
        String loginToken = testClient.getClientCredentialsOAuthAccessToken(oauthClientId, SECRET, "");

        //success - regular password grant but client is authenticated using POST parameters
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //success - regular password grant but client is authenticated using token
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("grant_type", "password")
            .param("client_id", oauthClientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //failure - client ID mismatch
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Basic " + new String(Base64.encode((oauthClientId + ":" + SECRET).getBytes())))
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());

        //failure - client ID mismatch
        getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + loginToken)
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("client_secret", SECRET)
            .param("username", developer.getUserName())
            .param("password", SECRET))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetClientCredentialsTokenForDefaultIdentityZone() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = getMockMvc().perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String,Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String,Object>>() {});
        assertNotNull(bodyMap.get("access_token"));
        Jwt jwt = JwtHelper.decode((String)bodyMap.get("access_token"));
        Map<String,Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        assertNotNull(claims.get(ClaimConstants.AUTHORITIES));
        assertNotNull(claims.get(ClaimConstants.AZP));
        assertNull(claims.get(ClaimConstants.USER_ID));
    }

    @Test
    public void clientCredentials_byDefault_willNotLockoutClientsUsingFormData() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        for(int i = 0; i < 6; i++){
           tryLoginWithWrongSecretInBody(clientId);
        }

        getMockMvc()
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
    public void clientCredentials_byDefault_WillNotLockoutDuringFailedBasicAuth() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        for(int i = 0; i < 6; i++){
            tryLoginWithWrongSecretInHeader(clientId);
        }

        login(clientId);
    }

    @Test
    public void clientCredentials_byDefault_WillNotLockoutDuringFailedBasicAuthAndFormData() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        for (int i = 0; i < 3; i++) {
            tryLoginWithWrongSecretInHeader(clientId);
            tryLoginWithWrongSecretInBody(clientId);
        }

        login(clientId);
    }

    private void tryLoginWithWrongSecretInHeader(String clientId) throws Exception {
        getMockMvc().perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + BADSECRET).getBytes())))
                .param("grant_type", "client_credentials")
        )
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
    }

    private void tryLoginWithWrongSecretInBody(String clientId) throws Exception {
        getMockMvc().perform(post("/oauth/token")
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
        getMockMvc().perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                .param("grant_type", "client_credentials")
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    @Test
    public void validateOldTokenAfterAddClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String,Object>>() {});
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);

        clientDetailsService.addClientSecret(clientId, "newSecret");
        getMockMvc().perform(post("/check_token")
            .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
            .param("token", access_token))
            .andDo(print())
            .andExpect(status().isOk());
    }

    @Test
    public void validateNewTokenAfterAddClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        clientDetailsService.addClientSecret(clientId, "newSecret");

        for (String secret : Arrays.asList(SECRET, "newSecret")) {
            String body = getMockMvc().perform(post("/oauth/token")
                                                   .accept(MediaType.APPLICATION_JSON_VALUE)
                                                   .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                                                   .param("grant_type", "client_credentials")
                                                   .param("client_id", clientId)
                                                   .param("client_secret", secret))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

            Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
            });
            String access_token = (String) bodyMap.get("access_token");
            assertNotNull(access_token);

            getMockMvc().perform(post("/check_token")
                                     .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                                     .param("token", access_token))
                .andExpect(status().isOk());
        }
    }

    @Test
    public void validateOldTokenAfterDeleteClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

        String body = getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String,Object>>() {});
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);

        clientDetailsService.addClientSecret(clientId, "newSecret");
        clientDetailsService.deleteClientSecret(clientId);

        MockHttpServletResponse response = getMockMvc().perform(post("/check_token")
                                                                    .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
                                                                    .param("token", access_token))
            .andExpect(status().isBadRequest())
            .andReturn().getResponse();

        InvalidTokenException tokenRevokedException = JsonUtils.readValue(response.getContentAsString(), TokenRevokedException.class);
        assertEquals("invalid_token", tokenRevokedException.getOAuth2ErrorCode());
        assertEquals("revocable signature mismatch", tokenRevokedException.getMessage());
    }

    @Test
    public void validateNewTokenBeforeDeleteClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        clientDetailsService.addClientSecret(clientId, "newSecret");

        String body = getMockMvc().perform(post("/oauth/token")
                                               .accept(MediaType.APPLICATION_JSON_VALUE)
                                               .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                                               .param("grant_type", "client_credentials")
                                               .param("client_id", clientId)
                                               .param("client_secret", SECRET))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String,Object>>() {});
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);


        clientDetailsService.deleteClientSecret(clientId);

        getMockMvc().perform(post("/check_token")
            .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
            .param("token", access_token))
            .andExpect(status().isOk());
    }

    @Test
    public void validateNewTokenAfterDeleteClientSecret() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        clientDetailsService.addClientSecret(clientId, "newSecret");
        clientDetailsService.deleteClientSecret(clientId);

        String body = getMockMvc().perform(post("/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":newSecret").getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String,Object>>() {});
        String access_token = (String) bodyMap.get("access_token");
        assertNotNull(access_token);

        getMockMvc().perform(post("/check_token")
            .header("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes())))
            .param("token", access_token))
            .andExpect(status().isOk());
    }


    @Test
    public void revokeOwnJWToken() throws Exception {
        IdentityZone defaultZone = identityZoneProvisioning.retrieve(IdentityZone.getUaa().getId());
        defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
        identityZoneProvisioning.update(defaultZone);

        try {
            BaseClientDetails client = new BaseClientDetails(
                generator.generate(),
                "",
                "openid",
                "client_credentials,password",
                "clients.write",
                 "http://redirect.uri");
            client.setClientSecret("secret");
            createClient(getMockMvc(), adminToken, client);

            //this is the token we will revoke
            String clientToken =
                    getClientCredentialsOAuthAccessToken(
                            getMockMvc(),
                            client.getClientId(),
                            client.getClientSecret(),
                            null,
                            null
                    );

            Jwt jwt = JwtHelper.decode(clientToken);
            Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
            String jti = (String) claims.get("jti");

            getMockMvc().perform(delete("/oauth/token/revoke/" + jti)
                    .header("Authorization", "Bearer " + clientToken))
                    .andExpect(status().isOk());

            tokenProvisioning.retrieve(jti);
        } catch (EmptyResultDataAccessException e) {
        } finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            identityZoneProvisioning.update(defaultZone);
        }
    }

    @Test
    public void revokeOtherClientToken() throws Exception {
        String resourceClientId = generator.generate();
        BaseClientDetails resourceClient = new BaseClientDetails(
                resourceClientId,
                "",
                "uaa.resource",
                "client_credentials,password",
                "uaa.resource",
                "http://redirect.uri");
        resourceClient.setClientSecret("secret");
        createClient(getMockMvc(), adminToken, resourceClient);

        BaseClientDetails client = new BaseClientDetails(
            generator.generate(),
            "",
            "openid",
            "client_credentials,password",
            "tokens.revoke",
             "http://redirect.uri");
        client.setClientSecret("secret");
        createClient(getMockMvc(), adminToken, client);

        //this is the token we will revoke
        String revokeAccessToken =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        client.getClientId(),
                        client.getClientSecret(),
                        "tokens.revoke",
                        null,
                        false
                );

        String tokenToBeRevoked =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        resourceClientId,
                        resourceClient.getClientSecret(),
                        null,
                        null,
                        true
                );

        getMockMvc().perform(delete("/oauth/token/revoke/" + tokenToBeRevoked)
                .header("Authorization", "Bearer " + revokeAccessToken))
                .andExpect(status().isOk());


        try {
            tokenProvisioning.retrieve(tokenToBeRevoked);
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException e) {
            //expected
        }
    }

    @Test
    public void revokeOtherClientTokenForbidden() throws Exception {
        String resourceClientId = generator.generate();
        BaseClientDetails resourceClient = new BaseClientDetails(
                resourceClientId,
                "",
                "uaa.resource",
                "client_credentials,password",
                "uaa.resource",
                "http://redirect.uri");
        resourceClient.setClientSecret("secret");
        createClient(getMockMvc(), adminToken, resourceClient);

        BaseClientDetails client = new BaseClientDetails(
            generator.generate(),
            "",
            "openid",
            "client_credentials,password",
            null,
            "http://redirect.uri");
        client.setClientSecret("secret");
        createClient(getMockMvc(), adminToken, client);

        //this is the token we will revoke
        String revokeAccessToken =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        client.getClientId(),
                        client.getClientSecret(),
                        null,
                        null,
                        false
                );

        String tokenToBeRevoked =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        resourceClientId,
                        resourceClient.getClientSecret(),
                        null,
                        null,
                        true
                );

        getMockMvc().perform(delete("/oauth/token/revoke/" + tokenToBeRevoked)
                .header("Authorization", "Bearer " + revokeAccessToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void revokeOpaqueTokenWithOpaqueToken() throws Exception {
        ScimUser scimUser = setUpUser("testUser" + generator.generate());

        String opaqueUserToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", scimUser.getUserName(), "secret", null);

        getMockMvc().perform(delete("/oauth/token/revoke/" + opaqueUserToken)
                .header("Authorization", "Bearer " + opaqueUserToken))
                .andExpect(status().isOk());

        try {
            tokenProvisioning.retrieve(opaqueUserToken);
        } catch (EmptyResultDataAccessException e) {
        }
    }

    @Test
    public void test_Revoke_Client_And_User_Tokens() throws Exception {
        BaseClientDetails client = getAClientWithClientsRead();
        BaseClientDetails otherClient = getAClientWithClientsRead();

        //this is the token we will revoke
        String readClientsToken =
            getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                client.getClientId(),
                client.getClientSecret(),
                null,
                null
            );

        //this is the token from another client
        String otherReadClientsToken =
            getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                otherClient.getClientId(),
                otherClient.getClientSecret(),
                null,
                null
            );

        //ensure our token works
        getMockMvc().perform(
            get("/oauth/clients")
            .header("Authorization", "Bearer "+readClientsToken)
        ).andExpect(status().isOk());

        //ensure we can't get to the endpoint without authentication
        getMockMvc().perform(
            get("/oauth/token/revoke/client/"+client.getClientId())
        ).andExpect(status().isUnauthorized());

        //ensure we can't get to the endpoint without correct scope
        getMockMvc().perform(
            get("/oauth/token/revoke/client/"+client.getClientId())
                .header("Authorization", "Bearer "+otherReadClientsToken)
        ).andExpect(status().isForbidden());

        //ensure that we have the correct error for invalid client id
        getMockMvc().perform(
            get("/oauth/token/revoke/client/notfound"+ generator.generate())
                .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isNotFound());

        //we revoke the tokens for that client
        getMockMvc().perform(
            get("/oauth/token/revoke/client/"+client.getClientId())
            .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isOk());

        //we should fail attempting to use the token
        getMockMvc().perform(
            get("/oauth/clients")
                .header("Authorization", "Bearer "+readClientsToken)
        )
            .andExpect(status().isUnauthorized())
            .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));


        ScimUser user = new ScimUser(null,
                                     generator.generate(),
                                     "Given Name",
                                     "Family Name");
        user.setPrimaryEmail(user.getUserName()+"@test.org");
        user.setPassword("password");

        user = createUser(getMockMvc(), adminToken, user);
        user.setPassword("password");

        String userInfoToken = getUserOAuthAccessToken(
            getMockMvc(),
            client.getClientId(),
            client.getClientSecret(),
            user.getUserName(),
            user.getPassword(),
            "openid"
        );

        //ensure our token works
        getMockMvc().perform(
            get("/userinfo")
                .header("Authorization", "Bearer "+userInfoToken)
        ).andExpect(status().isOk());

        //we revoke the tokens for that user
        getMockMvc().perform(
            get("/oauth/token/revoke/user/"+user.getId()+"notfound")
                .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isNotFound());


        //we revoke the tokens for that user
        getMockMvc().perform(
            get("/oauth/token/revoke/user/"+user.getId())
                .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isOk());

        getMockMvc().perform(
            get("/userinfo")
                .header("Authorization", "Bearer "+userInfoToken)
        )
            .andExpect(status().isUnauthorized())
            .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));


    }

    protected BaseClientDetails getAClientWithClientsRead() throws Exception {
        BaseClientDetails client = new BaseClientDetails(
            generator.generate(),
            "",
            "openid",
            "client_credentials,password",
            "clients.read",
            "http://redirect.uri");
        client.setClientSecret("secret");

        createClient(getMockMvc(), adminToken, client);
        return client;
    }

    @Test
    public void testGetClientCredentials_WithAuthoritiesExcluded_ForDefaultIdentityZone() throws Exception {
        Set<String> originalExclude = getWebApplicationContext().getBean(UaaTokenServices.class).getExcludedClaims();
        try {
            getWebApplicationContext().getBean(UaaTokenServices.class).setExcludedClaims(new HashSet<>(Arrays.asList(ClaimConstants.AUTHORITIES, ClaimConstants.AZP)));
            String clientId = "testclient" + generator.generate();
            String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
            setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);

            String body = getMockMvc().perform(post("/oauth/token")
                    .accept(MediaType.APPLICATION_JSON_VALUE)
                    .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                    .param("grant_type", "client_credentials")
                    .param("client_id", clientId)
                    .param("client_secret", SECRET))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            Map<String,Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String,Object>>() {});
            assertNotNull(bodyMap.get("access_token"));
            Jwt jwt = JwtHelper.decode((String)bodyMap.get("access_token"));
            Map<String,Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {});
            assertNull(claims.get(ClaimConstants.AUTHORITIES));
            assertNull(claims.get(ClaimConstants.AZP));
        }finally {
            getWebApplicationContext().getBean(UaaTokenServices.class).setExcludedClaims(originalExclude);
        }
    }


    @Test
    public void testGetClientCredentialsTokenForOtherIdentityZone() throws Exception {
        String subdomain = "testzone"+ generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        IdentityZoneHolder.clear();
        getMockMvc().perform(post("http://" + subdomain + ".localhost/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isOk());
    }

    @Test
    public void testGetClientCredentialsTokenForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
        String subdomain = "testzone"+ generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        IdentityZoneHolder.clear();
        getMockMvc().perform(post("http://localhost/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            //.header("Host", subdomain + ".localhost") - with updated Spring, this now works for request.getServerName
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetClientCredentialsTokenForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
        String clientId = "testclient" + generator.generate();
        String scopes = "space.*.developer,space.*.admin,org.*.reader,org.123*.admin,*.*,*";
        setUpClients(clientId, scopes, scopes, GRANT_TYPES, true);
        String subdomain = "testzone"+ generator.generate();
        setupIdentityZone(subdomain);
        getMockMvc().perform(post("http://" + subdomain + ".localhost/oauth/token")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("grant_type", "client_credentials")
            .param("client_id", clientId)
            .param("client_secret", SECRET))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetPasswordGrantInvalidPassword() throws Exception {
        String username = generator.generate()+"@test.org";
        IdentityZoneHolder.clear();
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI, Arrays.asList(OriginKeys.UAA));
        setUpUser(username);
        IdentityZoneHolder.clear();
        getMockMvc().perform(post("/oauth/token")
            .param("username", username)
            .param("password", "badsecret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isUnauthorized())
            .andExpect(content().string("{\"error\":\"unauthorized\",\"error_description\":\"Bad credentials\"}"));
    }


    @Test
    public void testGetPasswordGrantTokenExpiredPasswordForOtherZone() throws Exception {
        String username = generator.generate()+"@test.org";
        String subdomain = "testzone"+ generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider<UaaIdentityProviderDefinition> provider = setupIdentityProvider();
        UaaIdentityProviderDefinition config = provider.getConfig();
        if (config==null) {
            config = new UaaIdentityProviderDefinition(null,null);
        }
        PasswordPolicy passwordPolicy = new PasswordPolicy(6,128,1,1,1,0,6);
        config.setPasswordPolicy(passwordPolicy);
        provider.setConfig(config);
        identityProviderProvisioning.update(provider);
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));
        setUpUser(username);
        IdentityZoneHolder.clear();

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isOk());

        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(System.currentTimeMillis());
        cal.add(Calendar.YEAR, -1);
        Timestamp t = new Timestamp(cal.getTimeInMillis());
        assertEquals(1, getWebApplicationContext().getBean(JdbcTemplate.class).update("UPDATE users SET passwd_lastmodified = ? WHERE username = ?", t, username));

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isForbidden())
            .andExpect(content().string("{\"error\":\"access_denied\",\"error_description\":\"Your current password has expired. Please reset your password.\"}"));
    }

    @Test
    public void testGetPasswordGrantTokenForOtherZone() throws Exception {
        String username = generator.generate()+"@test.org";
        String subdomain = "testzone"+ generator.generate();
        String clientId = "testclient" + generator.generate();
        createNonDefaultZone(username, subdomain, clientId);

        MvcResult result = getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId))
            .andExpect(status().isOk())
            .andReturn();
        String claimsJSON = JwtHelper.decode(JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class).accessToken).getClaims();
        Claims claims = JsonUtils.readValue(claimsJSON, Claims.class);
        assertEquals(claims.getIss(), "http://" + subdomain.toLowerCase() + ".localhost:8080/uaa/oauth/token");
    }

    @Test
    public void testGetPasswordGrantForDefaultIdentityZoneFromOtherZoneFails() throws Exception {
        String username = generator.generate()+"@test.org";
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true);

        setUpUser(username);
        String subdomain = "testzone"+ generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        IdentityZoneHolder.clear();

        getMockMvc().perform(post("/oauth/token")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetPasswordGrantForOtherIdentityZoneFromDefaultZoneFails() throws Exception {
        String username = generator.generate()+"@test.org";
        String subdomain = "testzone"+ generator.generate();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider();

        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true);

        setUpUser(username);

        IdentityZoneHolder.clear();

        getMockMvc().perform(post("/oauth/token")
            .param("username", username)
            .param("password", "secret")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId)).andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetTokenScopesNotInAuthentication() throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(org.apache.commons.codec.binary.Base64.encodeBase64(("identity:identitysecret").getBytes()));

        ScimUser user = setUpUser(generator.generate()+"@test.org");

        String zoneadmingroup = "zones."+ generator.generate()+".admin";
        ScimGroup group = new ScimGroup(null,zoneadmingroup,IdentityZone.getUaa().getId());
        group = groupProvisioning.create(group);
        ScimGroupMember member = new ScimGroupMember(user.getId());
        groupMembershipManager.addMember(group.getId(),member);

        MockHttpSession session = getAuthenticatedSession(user);


        String state = generator.generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .header("Authorization", basicDigestHeaderValue)
            .header("Accept", MediaType.APPLICATION_JSON_VALUE)
            .session(session)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, "identity")
            .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");

        MvcResult result = getMockMvc().perform(authRequest).andExpect(status().is3xxRedirection()).andReturn();
        String location = result.getResponse().getHeader("Location");
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(location);
        String code = builder.build().getQueryParams().get("code").get(0);

        authRequest = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .header("Accept", MediaType.APPLICATION_JSON_VALUE)
            .param(OAuth2Utils.GRANT_TYPE, "authorization_code")
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param("code", code)
            .param(OAuth2Utils.CLIENT_ID, "identity")
            .param(OAuth2Utils.REDIRECT_URI, "http://localhost/test");
        result = getMockMvc().perform(authRequest).andExpect(status().is2xxSuccessful()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);

        OAuth2Authentication a1 = tokenServices.loadAuthentication(oauthToken.accessToken);

        assertEquals(4, a1.getOAuth2Request().getScope().size());
        assertThat(
            a1.getOAuth2Request().getScope(),
            containsInAnyOrder(new String[]{zoneadmingroup, "openid", "cloud_controller.read", "cloud_controller.write"})
        );

    }

    @Test
    public void testRevocablePasswordGrantTokenForDefaultZone() throws Exception {
        String tokenKey = "access_token";
        Map<String,Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(new HashedMap());
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String)tokenResponse.get(tokenKey);
        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>(){});
        assertNotNull("Token revocation signature must exist", claims.get(ClaimConstants.REVOCATION_SIGNATURE));
        assertTrue("Token revocation signature must be a string", claims.get(ClaimConstants.REVOCATION_SIGNATURE) instanceof String);
        assertTrue("Token revocation signature must have data", StringUtils.hasText((String) claims.get(ClaimConstants.REVOCATION_SIGNATURE)));
    }

    @Test
    public void testPasswordGrantTokenForDefaultZone_Opaque() throws Exception {
        Map<String,String> parameters = new HashedMap();
        parameters.put(REQUEST_TOKEN_FORMAT, OPAQUE);
        String tokenKey = "access_token";
        Map<String,Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(parameters);
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String)tokenResponse.get(tokenKey);
        assertThat("Token must be shorter than 37 characters", token.length(), lessThanOrEqualTo(36));

        RevocableToken revocableToken = getWebApplicationContext().getBean(RevocableTokenProvisioning.class).retrieve(token);
        assertNotNull("Token should have been stored in the DB", revocableToken);

        Jwt jwt = JwtHelper.decode(revocableToken.getValue());
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>(){});
        assertNotNull("Revocable claim must exist", claims.get(ClaimConstants.REVOCABLE));
        assertTrue("Token revocable claim must be set to true", (Boolean)claims.get(ClaimConstants.REVOCABLE));
    }

    @Test
    public void testNonDefaultZone_Jwt_Revocable() throws Exception {
        String username = generator.generate()+"@test.org";
        String subdomain = "testzone"+ generator.generate();
        String clientId = "testclient" + generator.generate();

        createNonDefaultZone(username, subdomain, clientId);
        IdentityZoneProvisioning zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        IdentityZone defaultZone = zoneProvisioning.retrieveBySubdomain(subdomain);
        try {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
            zoneProvisioning.update(defaultZone);
            MockHttpServletRequestBuilder post = post("/oauth/token")
                .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
                .header("Host", subdomain+".localhost")
                .param("username", username)
                .param("password", "secret")
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, clientId);
            Map<String, Object> tokenResponse = JsonUtils.readValue(
                getMockMvc().perform(post)
                    .andDo(print())
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {});
            validateRevocableJwtToken(tokenResponse, defaultZone);
        }finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            zoneProvisioning.update(defaultZone);
        }
    }

    protected void createNonDefaultZone(String username, String subdomain, String clientId) {
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        IdentityProvider provider = setupIdentityProvider();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI, Arrays.asList(provider.getOriginKey()));
        setUpUser(username);
        IdentityZoneHolder.clear();
    }

    @Test
    public void testDefaultZone_Jwt_Revocable() throws Exception {
        IdentityZoneProvisioning zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        IdentityZone defaultZone = zoneProvisioning.retrieve(IdentityZone.getUaa().getId());
        try {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
            zoneProvisioning.update(defaultZone);
            Map<String, String> parameters = new HashedMap();
            Map<String, Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(parameters);
            validateRevocableJwtToken(tokenResponse, defaultZone);
        }finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            zoneProvisioning.update(defaultZone);
        }
    }

    protected void validateRevocableJwtToken(Map<String, Object> tokenResponse, IdentityZone zone) throws Exception {
        String tokenKey = "access_token";
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String) tokenResponse.get(tokenKey);
        assertThat("Token must be longer than 36 characters", token.length(), greaterThan(36));

        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        assertNotNull("JTI Claim should be present", claims.get(JTI));
        String tokenId = (String) claims.get(JTI);

        IdentityZoneHolder.set(zone);
        RevocableToken revocableToken = getWebApplicationContext().getBean(RevocableTokenProvisioning.class).retrieve(tokenId);
        IdentityZoneHolder.clear();
        assertNotNull("Token should have been stored in the DB", revocableToken);


        jwt = JwtHelper.decode(revocableToken.getValue());
        claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        assertNotNull("Revocable claim must exist", claims.get(ClaimConstants.REVOCABLE));
        assertTrue("Token revocable claim must be set to true", (Boolean) claims.get(ClaimConstants.REVOCABLE));

        assertEquals(token, revocableToken.getValue());
    }


    @Test
    @Ignore(value = "We no longer support revocable=true parameter on the /oauth/token endpoint")
    public void testPasswordGrantTokenForDefaultZone_Revocable() throws Exception {
        Map<String,String> parameters = new HashedMap();
        parameters.put("revocable", "true");
        String tokenKey = "access_token";
        Map<String,Object> tokenResponse = testRevocablePasswordGrantTokenForDefaultZone(parameters);
        assertNotNull("Token must be present", tokenResponse.get(tokenKey));
        assertTrue("Token must be a string", tokenResponse.get(tokenKey) instanceof String);
        String token = (String)tokenResponse.get(tokenKey);
        assertThat("Token must be longer than 36 characters", token.length(), greaterThan(36));

        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>(){});
        assertNotNull("Revocable claim must exist", claims.get(ClaimConstants.REVOCABLE));
        assertTrue("Token revocable claim must be set to true", (Boolean)claims.get(ClaimConstants.REVOCABLE));

        RevocableToken revocableToken = getWebApplicationContext().getBean(RevocableTokenProvisioning.class).retrieve((String) claims.get(JTI));
        assertNotNull("Token should have been stored in the DB", revocableToken);
    }




    public Map<String,Object> testRevocablePasswordGrantTokenForDefaultZone(Map<String, String> parameters) throws Exception {
        String username = generator.generate()+"@test.org";
        String clientId = "testclient" + generator.generate();
        String scopes = "cloud_controller.read";
        setUpClients(clientId, scopes, scopes, "password,client_credentials", true, TEST_REDIRECT_URI, Arrays.asList(OriginKeys.UAA));
        setUpUser(username);

        MockHttpServletRequestBuilder post = post("/oauth/token")
            .header("Authorization", "Basic " + new String(Base64.encode((clientId + ":" + SECRET).getBytes())))
            .param("username", username)
            .param("password", "secret")
            .param(OAuth2Utils.RESPONSE_TYPE, "token")
            .param(OAuth2Utils.GRANT_TYPE, "password")
            .param(OAuth2Utils.CLIENT_ID, clientId);
        for (Map.Entry<String,String> entry : parameters.entrySet()) {
            post.param(entry.getKey(), entry.getValue());
        }
        return JsonUtils.readValue(
                getMockMvc().perform(post)
                    .andDo(print())
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {});

    }



    private ScimUser setUpUser(String username) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(username);
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setOrigin(OriginKeys.UAA);
        return jdbcScimUserProvisioning.createUser(scimUser, "secret");
    }

    public static class MockSecurityContext implements SecurityContext {

        private static final long serialVersionUID = -1386535243513362694L;

        private Authentication authentication;

        public MockSecurityContext(Authentication authentication) {
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
}
