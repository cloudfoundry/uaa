package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.ssl.Base64;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.SnippetUtils;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.MockSecurityContext;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.SCOPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.STATE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenEndpointDocs extends InjectedMockContextTest {

    private final ParameterDescriptor grantTypeParameter = parameterWithName(GRANT_TYPE).required().type(STRING).description("OAuth 2 grant type");
    private final ParameterDescriptor responseTypeParameter = parameterWithName(RESPONSE_TYPE).required().type(STRING).description("the type of token that should be issued.");
    private final ParameterDescriptor clientIdParameter = parameterWithName(CLIENT_ID).required().type(STRING).description("a unique string representing the registration information provided by the client, the recipient of the token");
    private final ParameterDescriptor clientSecretParameter = parameterWithName("client_secret").required().type(STRING).description("the secret passphrase configured for the OAuth client");
    private final ParameterDescriptor opaqueFormatParameter = parameterWithName(REQUEST_TOKEN_FORMAT).optional(null).type(STRING).description("<small><mark>UAA 3.3.0</mark></small> Can be set to '"+ OPAQUE+"' to retrieve an opaque and revocable token.");
    private final ParameterDescriptor scopeParameter = parameterWithName(SCOPE).optional(null).type(STRING).description("The list of scopes requested for the token. Use when you wish to reduce the number of scopes the token will have.");

    private final SnippetUtils.ConstrainableHeader authorizationHeader = SnippetUtils.headerWithName("Authorization");

    private ScimUser user;

    @Test
    public void getTokenUsingAuthCodeGrant() throws Exception {
        createUser();
        String cfAccessToken = getUserOAuthAccessToken(
            getMockMvc(),
            "cf",
            "",
            user.getUserName(),
            user.getPassword(),
            "uaa.user"
        );

        String redirect = "https://uaa.cloudfoundry.com/redirect/cf";
        MockHttpServletRequestBuilder getAuthCode = get("/oauth/authorize")
            .header("Authorization", "Bearer " + cfAccessToken)
            .param(RESPONSE_TYPE, "code")
            .param(CLIENT_ID, "login")
            .param(REDIRECT_URI, redirect)
            .param(STATE, new RandomValueStringGenerator().generate());

        MockHttpServletResponse authCodeResponse = getMockMvc().perform(getAuthCode)
            .andExpect(status().isFound())
            .andReturn()
            .getResponse();

        UriComponents location = UriComponentsBuilder.fromUri(URI.create(authCodeResponse.getHeader("Location"))).build();
        String code = location.getQueryParams().getFirst("code");

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(CLIENT_ID, "login")
            .param("client_secret", "loginsecret")
            .param(GRANT_TYPE, "authorization_code")
            .param(RESPONSE_TYPE, "token")
            .param("code", code)
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param(REDIRECT_URI, redirect);

        Snippet requestParameters = requestParameters(
            responseTypeParameter,
            clientIdParameter,
            parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request"), SnippetUtils.type.value(STRING)),
            parameterWithName("code").description("the authorization code, obtained from /oauth/authorize, issued for the user").attributes(SnippetUtils.constraints.value("Required"), SnippetUtils.type.value(STRING)),
            grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
            clientSecretParameter,
            opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("the access token for the user to whom the authorization code was issued"),
            fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
            fieldWithPath("expires_in").description("number of seconds until token expiry"),
            fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("refresh_token").description("an OAuth refresh token for refresh grants"),
            fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        getMockMvc().perform(postForToken)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }

    @Test
    public void getTokenUsingClientCredentialGrant() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(CLIENT_ID, "login")
            .param("client_secret", "loginsecret")
            .param(GRANT_TYPE, "client_credentials")
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            responseTypeParameter,
            clientIdParameter,
            grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
            clientSecretParameter,
            opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("the access token"),
            fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
            fieldWithPath("expires_in").description("number of seconds until token expiry"),
            fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        getMockMvc().perform(postForToken)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }

    @Test
    public void getTokenUsingClientCredentialGrantWithAuthorizationHeader() throws Exception {

        String clientAuthorization = new String(Base64.encodeBase64("login:loginsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(GRANT_TYPE, "client_credentials")
            .param(RESPONSE_TYPE, "token")
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .header("Authorization", "Basic " + clientAuthorization);

        Snippet requestParameters = requestParameters(
                responseTypeParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
                opaqueFormatParameter
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Base64 encoded client details in the format: `Basic client_id:client_secret`"));

        Snippet responseFields = responseFields(
                fieldWithPath("access_token").description("the access token"),
                fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
                fieldWithPath("expires_in").description("number of seconds until token expiry"),
                fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
                fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        getMockMvc().perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, requestHeaders, responseFields));
    }

    @Test
    public void getTokenUsingPasswordGrant() throws Exception {
        createUser();
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(CLIENT_ID, "app")
            .param("client_secret", "appclientsecret")
            .param(GRANT_TYPE, "password")
            .param("username", user.getUserName())
            .param("password", user.getPassword())
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            responseTypeParameter,
            clientIdParameter,
            grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
            clientSecretParameter,
            parameterWithName("username").required().type(STRING).description("the username for the user trying to get a token"),
            parameterWithName("password").required().type(STRING).description("the password for the user trying to get a token"),
            opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("the access token"),
            fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
            fieldWithPath("expires_in").description("number of seconds until token expiry"),
            fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("refresh_token").description("an OAuth refresh token for refresh grants"),
            fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        getMockMvc().perform(postForToken)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }


    @Test
    public void getTokenUsingUserTokenGrant() throws Exception {
        createUser();
        String token = MockMvcUtils.getUserOAuthAccessToken(getMockMvc(),
                                                            "oauth_showcase_user_token",
                                                            "secret",
                                                            user.getUserName(),
                                                            "secr3T",
                                                            "uaa.user",
                                                            null,
                                                            true);
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .header(AUTHORIZATION, "Bearer "+token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(CLIENT_ID, "app")
            .param(GRANT_TYPE, GRANT_TYPE_USER_TOKEN)
            .param(SCOPE, "openid")
            .param(REQUEST_TOKEN_FORMAT, "jwt")
            .param(RESPONSE_TYPE, "token");

        Snippet requestHeaders = requestHeaders(
            authorizationHeader.required().description("A bearer token on behalf of a user with the scope uaa.user present")
        );

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("Response type of the grant, should be set to `token`"),
            clientIdParameter.description("The client ID of the receiving client, this client must have `refresh_token` grant type"),
            grantTypeParameter.description("The type of token grant requested, in this case `"+GRANT_TYPE_USER_TOKEN+"`"),
            opaqueFormatParameter.description("This parameter is ignored. The refresh_token will always be opaque"),
            scopeParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("Always null"),
            fieldWithPath("token_type").description("The type of the access token issued, always `bearer`"),
            fieldWithPath("expires_in").description("Number of seconds of lifetime for an access_token, when retrieved"),
            fieldWithPath("scope").description("Space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("refresh_token").description("An OAuth refresh token for refresh grants"),
            fieldWithPath("jti").description("A globally unique identifier for this refresh token")
        );

        getMockMvc().perform(postForToken)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, requestParameters, responseFields));
    }

    @Test
    public void getTokenWithClientAuthInHeader() throws Exception {
        createUser();
        String clientAuthorization = new String(Base64.encodeBase64("app:appclientsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .header("Authorization", "Basic " + clientAuthorization)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(GRANT_TYPE, "password")
            .param("username", user.getUserName())
            .param("password", user.getPassword())
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            responseTypeParameter,
            grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
            parameterWithName("username").required().type(STRING).description("the username for the user trying to get a token"),
            parameterWithName("password").required().type(STRING).description("the password for the user trying to get a token"),
            opaqueFormatParameter
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Base64 encoded client details in the format: `Basic client_id:client_secret`"));

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("the access token"),
            fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
            fieldWithPath("expires_in").description("number of seconds until token expiry"),
            fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("refresh_token").description("an OAuth refresh token for refresh grants"),
            fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        getMockMvc().perform(postForToken)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, requestHeaders, responseFields));
    }

    @Test
    public void getTokenUsingPasscode() throws Exception {
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"").get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, Arrays.asList(UaaAuthority.fromAuthorities("uaa.user")));

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/passcode")
            .accept(APPLICATION_JSON)
            .session(session);

        String passcode = JsonUtils.readValue(
            getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(),
            String.class);

        String clientAuthorization = new String(Base64.encodeBase64("app:appclientsecret".getBytes()));

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .header("Authorization", "Basic " + clientAuthorization)
            .param(GRANT_TYPE, "password")
            .param("passcode", passcode)
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            responseTypeParameter,
            grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
            parameterWithName("passcode").required().type(STRING).description("the one-time passcode for the user which can be retrieved by going to `/passcode`"),
            opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("the access token"),
            fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
            fieldWithPath("expires_in").description("number of seconds until token expiry"),
            fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("refresh_token").description("an OAuth refresh token for refresh grants"),
            fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Base64 encoded client details in the format: `Basic client_id:client_secret`"));
        getMockMvc().perform(postForToken)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, requestHeaders, responseFields))
            .andExpect(status().isOk());
    }

    @Test
    public void refreshToken() throws Exception {
        createUser();
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(CLIENT_ID, "app")
            .param("client_secret", "appclientsecret")
            .param(GRANT_TYPE, "password")
            .param("username", user.getUserName())
            .param("password", user.getPassword())
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param(RESPONSE_TYPE, "token");

        MvcResult mvcResult = getMockMvc().perform(postForToken).andExpect(status().isOk()).andReturn();
        OAuth2RefreshToken refreshToken = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), CompositeAccessToken.class).getRefreshToken();

        MockHttpServletRequestBuilder postForRefreshToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(CLIENT_ID, "app")
            .param("client_secret", "appclientsecret")
            .param(GRANT_TYPE, "refresh_token")
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param("refresh_token", refreshToken.getValue());

        Snippet requestParameters = requestParameters(
            grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `refresh_token`"),
            clientIdParameter,
            clientSecretParameter,
            parameterWithName("refresh_token").required().type(STRING).description("the refresh_token that was returned along with the access token."),
            opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("the access token"),
            fieldWithPath("refresh_token").description("the refresh token"),
            fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
            fieldWithPath("expires_in").description("number of seconds until token expiry"),
            fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        getMockMvc().perform(postForRefreshToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields))
                .andExpect(status().isOk())
                .andReturn();
    }

    private void createUser() throws Exception {
        TestClient testClient = new TestClient(getMockMvc());
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", null);
        user = new ScimUser(null, new RandomValueStringGenerator().generate()+"@test.org", "name", "familyName");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = MockMvcUtils.createUser(getMockMvc(), adminToken, user);
        user.setPassword("secr3T");
    }

    @Test
    public void getIdTokenUsingAuthCodeGrant() throws Exception {
        createUser();
        String cfAccessToken = getUserOAuthAccessToken(
            getMockMvc(),
            "cf",
            "",
            user.getUserName(),
            user.getPassword(),
            "uaa.user"
        );

        String redirect = "https://uaa.cloudfoundry.com/redirect/cf";
        MockHttpServletRequestBuilder getAuthCode = get("/oauth/authorize")
            .header("Authorization", "Bearer " + cfAccessToken)
            .param(RESPONSE_TYPE, "code")
            .param(CLIENT_ID, "login")
            .param(REDIRECT_URI, redirect)
            .param(STATE, new RandomValueStringGenerator().generate());

        MockHttpServletResponse authCodeResponse = getMockMvc().perform(getAuthCode)
            .andExpect(status().isFound())
            .andReturn()
            .getResponse();

        UriComponents location = UriComponentsBuilder.fromUri(URI.create(authCodeResponse.getHeader("Location"))).build();
        String code = location.getQueryParams().getFirst("code");

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_FORM_URLENCODED)
            .param(CLIENT_ID, "login")
            .param("client_secret", "loginsecret")
            .param(GRANT_TYPE, "authorization_code")
            .param(RESPONSE_TYPE, "id_token")
            .param("code", code)
            .param(REQUEST_TOKEN_FORMAT, OPAQUE)
            .param(REDIRECT_URI, redirect);

        Snippet requestParameters = requestParameters(
            responseTypeParameter,
            clientIdParameter,
            parameterWithName(REDIRECT_URI).type(STRING).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request")),
            parameterWithName("code").required().type(STRING).description("the authorization code, obtained from /oauth/authorize, issued for the user"),
            grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
            clientSecretParameter,
            opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("access_token").description("the access token for the user to whom the authorization code was issued"),
            fieldWithPath("id_token").description("the OpenID Connect ID token for the user to whom the authorization code was issued"),
            fieldWithPath("token_type").description("the type of the access token issued, i.e. `bearer`"),
            fieldWithPath("expires_in").description("number of seconds until token expiry"),
            fieldWithPath("scope").description("space-delimited list of scopes authorized by the user for this client"),
            fieldWithPath("refresh_token").description("an OAuth refresh token for refresh grants"),
            fieldWithPath("jti").description("a globally unique identifier for this token")
        );

        getMockMvc().perform(postForToken)
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }

    @Test
    public void revokeAllTokens_forAUser() throws Exception {
        String adminToken =  getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                "admin",
                "adminsecret",
                "",
                null
        );
        BaseClientDetails client = createClient(adminToken);

        createUser();
        String userInfoToken = getUserOAuthAccessToken(
                getMockMvc(),
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                ""
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Bearer token with uaa.admin scope."));
        Snippet pathParameters = pathParameters(parameterWithName("userId").description("The identifier for the user to revoke all tokens for"));
        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/oauth/token/revoke/user/{userId}", user.getId());

        getMockMvc().perform(get
                        .header("Authorization", "Bearer "+adminToken))
                        .andExpect(status().isOk())
                        .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters));

        getMockMvc().perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer "+userInfoToken))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));
    }

    @Test
    public void revokeAllTokens_forAClient() throws Exception {
        String adminToken =  getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                "admin",
                "adminsecret",
                "",
                null,
                true
        );
        BaseClientDetails client = createClient(adminToken);
        String readClientsToken =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        client.getClientId(),
                        client.getClientSecret(),
                        null,
                        null,
                        true
                );
        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Bearer token with uaa.admin scope."));
        Snippet pathParameters = pathParameters(parameterWithName("clientId").description("The identifier for the client to revoke all tokens for"));
        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/oauth/token/revoke/client/{clientId}", client.getClientId());
        getMockMvc().perform(get
                .header("Authorization", "Bearer "+ adminToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters));

        getMockMvc().perform(
                get("/oauth/clients")
                .header("Authorization", "Bearer "+readClientsToken))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));
    }

    @Test
    public void revokeSingleToken() throws Exception {
        String adminToken =  getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                "admin",
                "adminsecret",
                "",
                null,
                true
        );

        BaseClientDetails client = createClient(adminToken);
        createUser();

        String userInfoToken = getUserOAuthAccessToken(
                getMockMvc(),
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "",
                IdentityZoneHolder.get(),
                true
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Bearer token with tokens.revoke scope. If token being revoked is for self, use the token to be revoked in this header."));
        Snippet pathParameters = pathParameters(parameterWithName("tokenId").description("The identifier for the token to be revoked. For JWT tokens use the jti claim in the token."));

        MockHttpServletRequestBuilder delete = RestDocumentationRequestBuilders.delete("/oauth/token/revoke/{tokenId}", userInfoToken);

        getMockMvc().perform(delete
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters));
    }



    private BaseClientDetails createClient(String token) throws Exception {
        BaseClientDetails client = new BaseClientDetails(
                new RandomValueStringGenerator().generate(),
                "",
                "openid",
                "client_credentials,password",
                "clients.read");
        client.setClientSecret("secret");
        BaseClientDetails clientDetails = MockMvcUtils.createClient(getMockMvc(), token, client);
        clientDetails.setClientSecret("secret");
        return clientDetails;
    }
}
