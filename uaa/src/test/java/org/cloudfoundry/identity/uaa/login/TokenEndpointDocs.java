package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.JUnitRestDocumentationExtension;
import org.cloudfoundry.identity.uaa.test.SnippetUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.ManualRestDocumentation;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.MockSecurityContext;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getMfaCodeFromCredentials;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.createLocalSamlIdpDefinition;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.SCOPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.STATE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(JUnitRestDocumentationExtension.class)
class TokenEndpointDocs extends AbstractTokenMockMvcTests {

    private final ParameterDescriptor grantTypeParameter = parameterWithName(GRANT_TYPE).required().type(STRING).description("OAuth 2 grant type");

    private final ParameterDescriptor clientIdParameter = parameterWithName(CLIENT_ID).optional(null).type(STRING).description("A unique string representing the registration information provided by the client, the recipient of the token. Optional if it is passed as part of the Basic Authorization header or as part of the client_assertion.");
    private final ParameterDescriptor clientSecretParameter = parameterWithName("client_secret").optional(null).type(STRING).description("The [secret passphrase configured](#change-secret) for the OAuth client. Optional if it is passed as part of the Basic Authorization header or if client_assertion is sent as part of private_key_jwt authentication.");
    private final ParameterDescriptor opaqueFormatParameter = parameterWithName(REQUEST_TOKEN_FORMAT).optional(null).type(STRING).description("Can be set to `" + OPAQUE.getStringValue() + "` to retrieve an opaque and revocable token or to `" + JWT.getStringValue() + "` to retrieve a JWT token. If not set the zone setting config.tokenPolicy.jwtRevocable is used.");
    private final ParameterDescriptor scopeParameter = parameterWithName(SCOPE).optional(null).type(STRING).description("The list of scopes requested for the token. Use when you wish to reduce the number of scopes the token will have.");
    private final ParameterDescriptor loginHintParameter = parameterWithName("login_hint").optional(null).type(STRING).description("<small><mark>UAA 75.5.0</mark></small> Indicates the identity provider to be used. The passed string has to be a URL-Encoded JSON Object, containing the field `origin` with value as `origin_key` of an identity provider. Note that this identity provider must support the grant type `password`.");
    private final ParameterDescriptor codeVerifier = parameterWithName(PkceValidationService.CODE_VERIFIER).description("<small><mark>UAA 75.5.0</mark></small> [PKCE](https://tools.ietf.org/html/rfc7636) Code Verifier. A `code_verifier` parameter must be provided if a `code_challenge` parameter was present in the previous call to `/oauth/authorize`. The `code_verifier` must match the used `code_challenge` (according to the selected `code_challenge_method`)").attributes(key("constraints").value("Optional"), key("type").value(STRING));

    private final FieldDescriptor accessTokenFieldDescriptor = fieldWithPath("access_token").description("An OAuth2 [access token](https://tools.ietf.org/html/rfc6749#section-1.4). When `token_format=opaque` is requested this value will be a random string that can only be validated using the UAA's `/check_token` or `/introspect` endpoints. When `token_format=jwt` is requested, this token will be a [JSON Web Token](https://tools.ietf.org/html/rfc7519) suitable for offline validation by OAuth2 Resource Servers.");
    private final FieldDescriptor idTokenFieldDescriptor = fieldWithPath("id_token").description("An OpenID Connect [ID token](http://openid.net/specs/openid-connect-core-1_0.html#IDToken). This portion of the token response is only returned when clients are configured with the scope `openid`, the `response_type` includes `id_token`, and the user has granted approval to the client for the `openid` scope.");
    private final FieldDescriptor refreshTokenFieldDescriptor = fieldWithPath("refresh_token").description("An OAuth2 [refresh token](https://tools.ietf.org/html/rfc6749#section-6). Clients typically use the refresh token to obtain a new access token without the need for the user to authenticate again. They do this by calling `/oauth/token` with `grant_type=refresh_token`. See [here](#refresh-token) for more information. A refresh token will only be issued to [clients](#clients) that have `refresh_token` in their list of `authorized_grant_types`.");
    private final FieldDescriptor scopeFieldDescriptorWhenUserToken = fieldWithPath("scope").description("A space-delimited list of scopes authorized by the user for this client. This list is the intersection of the scopes configured on the [client](#clients), the group memberships of the [user](#users), and the user's approvals (when `autoapprove: true` is not configured on the [client](#clients)).");
    private final FieldDescriptor scopeFieldDescriptorWhenClientCredentialsToken = fieldWithPath("scope").description("A space-delimited list of scopes authorized for this client. This list is derived from the `authorities` configured on the [client](#clients).");
    private final FieldDescriptor expiresInFieldDescriptor = fieldWithPath("expires_in").description("The number of seconds until the access token expires.");
    private final FieldDescriptor jtiFieldDescriptor = fieldWithPath("jti").description("A globally unique identifier for this access token. This identifier is used when [revoking tokens](#revoke-tokens).");
    private final FieldDescriptor tokenTypeFieldDescriptor = fieldWithPath("token_type").description("The type of the access token issued. This field is mandated in [RFC 6749](https://tools.ietf.org/html/rfc6749#section-7.1). In the UAA, the only supported `token_type` is `bearer`.");

    private final ParameterDescriptor clientAssertionType = parameterWithName(JwtClientAuthentication.CLIENT_ASSERTION_TYPE).optional(null).description("<small><mark>UAA 76.23.0</mark></small> [RFC 7523](https://tools.ietf.org/html/rfc7523) describes the type. Must be set to `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` if `client_assertion` parameter is present.").attributes(key("constraints").value("Optional"), key("type").value(STRING));

    private final ParameterDescriptor clientAssertion = parameterWithName(JwtClientAuthentication.CLIENT_ASSERTION).optional(null).description("<small><mark>UAA 76.23.0</mark></small> Client authentication using method [private_key_jwt](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication). Optional as replacement of methods client_secret_basic or client_secret_post using secrets. The client needs to have a valid [JWT confiuration](#change-client-jwt) for trust to JWT in client_assertion.").attributes(key("constraints").value("Optional"), key("type").value(STRING));

    private final String codeDescription = "the authorization code, obtained from `/oauth/authorize`, issued for the user";

    private final SnippetUtils.ConstrainableHeader authorizationHeader = SnippetUtils.headerWithName("Authorization");

    private Snippet listTokenResponseFields = responseFields(
            fieldWithPath("[].zoneId").type(STRING).description("The zone ID for the token"),
            fieldWithPath("[].tokenId").type(STRING).description("The unique ID for the token"),
            fieldWithPath("[].clientId").type(STRING).description("Client ID for this token, will always match the client_id claim in the access token used for this call"),
            fieldWithPath("[].userId").optional().type(STRING).description("User ID for this token, will always match the user_id claim in the access token used for this call"),
            fieldWithPath("[].format").type(STRING).description("What format was requested, possible values OPAQUE or JWT"),
            fieldWithPath("[].expiresAt").type(NUMBER).description("Token expiration date, as a epoch timestamp, in milliseconds between the expires time and midnight, January 1, 1970 UTC."),
            fieldWithPath("[].issuedAt").type(NUMBER).description("Token issue date as, a epoch timestamp, in milliseconds between the issued time and midnight, January 1, 1970 UTC."),
            fieldWithPath("[].scope").type(STRING).description("Comma separated list of scopes this token holds, up to 1000 characters"),
            fieldWithPath("[].responseType").type(STRING).description("Response type requested during the token request, possible values ACCESS_TOKEN or REFRESH_TOKEN"),
            fieldWithPath("[].value").optional().type(STRING).description("Access token value will always be null")
    );

    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).description("May include this header to administer another zone if using `zones.<zoneId>.admin` or `uaa.admin` scope against the default UAA zone.").optional();
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin` scope/token, indicates what zone this request goes to by supplying a subdomain.");
    private static final HeaderDescriptor CLIENT_BASIC_AUTH_HEADER = headerWithName(HttpHeaders.AUTHORIZATION).optional().description("Client ID and secret may be passed as a basic authorization header, per <a href=\"https://tools.ietf.org/html/rfc6749#section-2.3.1\">RFC 6749</a> or as request parameters.");

    private ScimUser user;

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    @BeforeEach
    void setUpContext(ManualRestDocumentation manualRestDocumentation) {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .apply(documentationConfiguration(manualRestDocumentation)
                        .uris().withPort(80)
                        .and()
                        .snippets()
                        .withTemplateFormat(markdown()))
                .build();
        testClient = new TestClient(mockMvc);
    }

    @BeforeEach
    void createTestUser() throws Exception {
        if (user == null) {
            createUser();
        }
    }

    @Test
    void getTokenUsingAuthCodeGrant() throws Exception {

        String cfAccessToken = getUserOAuthAccessToken(
                mockMvc,
                "cf",
                "",
                user.getUserName(),
                user.getPassword(),
                "uaa.user"
        );

        String redirect = "http://localhost/redirect/cf";
        MockHttpServletRequestBuilder getAuthCode = get("/oauth/authorize")
                .header("Authorization", "Bearer " + cfAccessToken)
                .param(RESPONSE_TYPE, "code")
                .param(CLIENT_ID, "login")
                .param(REDIRECT_URI, redirect)
                .param(PkceValidationService.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE)
                .param(PkceValidationService.CODE_CHALLENGE_METHOD, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256)
                .param(STATE, new RandomValueStringGenerator().generate());

        MockHttpServletResponse authCodeResponse = mockMvc.perform(getAuthCode)
                .andExpect(status().isFound())
                .andReturn()
                .getResponse();

        UriComponents location = UriComponentsBuilder.fromUri(URI.create(authCodeResponse.getHeader("Location"))).build();
        String code = location.getQueryParams().getFirst("code");

        String clientAuthBase64 = new String(org.springframework.security.crypto.codec.Base64.encode(("login:loginsecret".getBytes())));
        Snippet headerFields = requestHeaders(CLIENT_BASIC_AUTH_HEADER);

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .header(HttpHeaders.AUTHORIZATION, "Basic " + clientAuthBase64)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_secret", "loginsecret")
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, redirect);

        Snippet requestParameters = requestParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request"), SnippetUtils.type.value(STRING)),
                parameterWithName("code").description(codeDescription).attributes(SnippetUtils.constraints.value("Required"), SnippetUtils.type.value(STRING)),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
                clientSecretParameter.description("<small><mark>UAA 75.21.0</mark></small> Optional and can be omitted if client has configured allowpublic and [PKCE](https://tools.ietf.org/html/rfc7636) with `code_challenge_method=S256` is used to create to `code`."),
                clientAssertion,
                clientAssertionType,
                codeVerifier,
                opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                idTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), headerFields, requestParameters, responseFields));
    }

    @Test
    void getTokenUsingClientCredentialGrant() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_secret", "loginsecret")
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(SCOPE, "scim.write")
                .param(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        Snippet requestParameters = requestParameters(
                clientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
                clientSecretParameter,
                clientAssertion,
                clientAssertionType,
                scopeParameter,
                opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenClientCredentialsToken,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }

    @Test
    void getTokenUsingClientCredentialGrantWithAuthorizationHeader() throws Exception {

        String clientAuthorization = new String(Base64.encodeBase64("login:loginsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                .param(SCOPE, "scim.write")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .header("Authorization", "Basic " + clientAuthorization);

        Snippet requestParameters = requestParameters(
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
                scopeParameter,
                opaqueFormatParameter
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Base64 encoded client details in the format: `Basic client_id:client_secret`"));

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenClientCredentialsToken,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, requestHeaders, responseFields));
    }

    @Test
    void getTokenUsingPasswordGrant() throws Exception {
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_secret", "appclientsecret")
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("login_hint", "{\"origin\":\"uaa\"}");

        Snippet requestParameters = requestParameters(
                clientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
                clientSecretParameter,
                clientAssertion,
                clientAssertionType,
                parameterWithName("username").required().type(STRING).description("the username for the user trying to get a token"),
                parameterWithName("password").required().type(STRING).description("the password for the user trying to get a token"),
                opaqueFormatParameter,
                loginHintParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                idTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }

    @Test
    void getTokenUsingMfaPasswordGrant() throws Exception {

        setupForMfaPasswordGrant(user.getId());

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_secret", "appclientsecret")
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param("mfaCode", String.valueOf(getMfaCodeFromCredentials(credentials)))
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("login_hint", "{\"origin\":\"uaa\"}");

        Snippet requestParameters = requestParameters(
                clientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
                clientSecretParameter,
                clientAssertion,
                clientAssertionType,
                parameterWithName("username").required().type(STRING).description("the username for the user trying to get a token"),
                parameterWithName("password").required().type(STRING).description("the password for the user trying to get a token"),
                parameterWithName("mfaCode").required().type(NUMBER).description("A one time passcode from a registered multi-factor generator"),
                opaqueFormatParameter,
                loginHintParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                idTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }

    @Test
    void getTokenUsingUserTokenGrant() throws Exception {
        String token = MockMvcUtils.getUserOAuthAccessToken(mockMvc,
                "oauth_showcase_user_token",
                "secret",
                user.getUserName(),
                "secr3T",
                "uaa.user",
                null,
                true);
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .header(AUTHORIZATION, "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param(GRANT_TYPE, GRANT_TYPE_USER_TOKEN)
                .param(SCOPE, "openid")
                .param(REQUEST_TOKEN_FORMAT, "jwt");

        Snippet requestHeaders = requestHeaders(
                authorizationHeader.required().description("A bearer token on behalf of a user with the scope uaa.user present")
        );

        Snippet requestParameters = requestParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `refresh_token` grant type"),
                grantTypeParameter.description("The type of token grant requested, in this case `" + GRANT_TYPE_USER_TOKEN + "`"),
                opaqueFormatParameter.description("This parameter is ignored. The refresh_token will always be opaque"),
                scopeParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, requestParameters, responseFields));
    }

    @Test
    void getTokenUsingSaml2BearerGrant() throws Exception {
        SamlTestUtils samlTestUtils = new SamlTestUtils();
        samlTestUtils.initializeSimple();

        String subdomain = "sds1ko";
        //all our SAML defaults use :8080/uaa/ so we have to use that here too
        String host = subdomain + ".localhost";
        String fullPath = "/uaa/oauth/token/alias/" + subdomain + ".cloudfoundry-saml-login";
        String origin = subdomain + ".cloudfoundry-saml-login";

        MockMvcUtils.IdentityZoneCreationResult zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, this.webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());

        //Mock an IDP metadata
        String idpMetadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"sds1ko.cloudfoundry-saml-login\" entityID=\"sds1ko.cloudfoundry-saml-login\"><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#sds1ko.cloudfoundry-saml-login\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>KuAftbgDBKaYcfFFu+PW7LfVzcs=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>FRd4w/nyR7Zj2673Q45lHv9kJNdPuAnubxlmqgGfEYR0HFPiNMkHo+Kk7HAzW07SvogyL7N38QMdJFeMIu1n5UleObzRqwJMWwqdrMtE4m4AHX+KwFwRWB9j8riNPiUCURjFsiJLmKfkxAy/hk3HrIEttaV0/Dvj9dYSQYc2XsU=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
                "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
                "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
                "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
                "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
                "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
                "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
                "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
                "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
                "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
                "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
                "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
                "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
                "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
                "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
                "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
                "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
                "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
                "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
                "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
                "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
                "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
                "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
                "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
                "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
                "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
                "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
                "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
                "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
                "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
                "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
                "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
                "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
                "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
                "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
                "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
                "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
                "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
                "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
                "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
                "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
                "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
                "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://sds1ko.localhost:8080/uaa/saml/idp/SSO/alias/sds1ko.cloudfoundry-saml-login\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://sds1ko.localhost:8080/uaa/saml/idp/SSO/alias/sds1ko.cloudfoundry-saml-login\"/></md:IDPSSODescriptor></md:EntityDescriptor>";

        //create an IDP in the default zone
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(origin, zone.getIdentityZone().getId(), idpMetadata);
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getIdentityZone().getId());
        provider.setName(origin);
        provider.setOriginKey(origin);

        IdentityZoneHolder.set(zone.getIdentityZone());
        identityProviderProvisioning.create(provider, zone.getIdentityZone().getId());
        IdentityZoneHolder.clear();

        String assertion = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iYTRoNDQyMmk2aGY1MGQwNWI3Y2g1MmZoZWZoNmhoIiBJc3N1ZUluc3RhbnQ9IjIwMjMtMTItMTJUMTg6NTQ6NTIuMTI4WiIgVmVyc2lvbj0iMi4wIiB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiPjxzYW1sMjpJc3N1ZXI-c2RzMWtvLmNsb3VkZm91bmRyeS1zYW1sLWxvZ2luPC9zYW1sMjpJc3N1ZXI-PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI-PGRzOlNpZ25lZEluZm8-PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8-PGRzOlJlZmVyZW5jZSBVUkk9IiNhNGg0NDIyaTZoZjUwZDA1YjdjaDUyZmhlZmg2aGgiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjxlYzpJbmNsdXNpdmVOYW1lc3BhY2VzIHhtbG5zOmVjPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIFByZWZpeExpc3Q9InhzIi8-PC9kczpUcmFuc2Zvcm0-PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT5FWVRZSitDMFBMMWtheGE5K2Z4YXVEdUZZd0E9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8-PGRzOlNpZ25hdHVyZVZhbHVlPklLMVoycWl6Q1pCT0JSS3F0bFQwb2JucDNoM1NRUk1kdTI3MUlUQytEa3c1RC9pRFFtbHVOZzc3SnFnWjc0NGFhY3JZNGQvVFJvMVl2dlQ5cm5PcGludmMzMGtjS0o5Y0IrOThWRXBkZjVRT2hNZEJyOVZjQllhWDVtWUdqZWNqZUlSNkZqWlY4eEI3Y0JCY2hrT2xzcmZlcnRwRS84S3JBeFJvV2hJSkxMTT08L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSURTVENDQXJLZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRUUZBREI4TVFzd0NRWURWUVFHRXdKaGR6RU9NQXdHQTFVRUNCTUYKWVhKMVltRXhEakFNQmdOVkJBb1RCV0Z5ZFdKaE1RNHdEQVlEVlFRSEV3VmhjblZpWVRFT01Bd0dBMVVFQ3hNRllYSjFZbUV4RGpBTQpCZ05WQkFNVEJXRnlkV0poTVIwd0d3WUpLb1pJaHZjTkFRa0JGZzVoY25WaVlVQmhjblZpWVM1aGNqQWVGdzB4TlRFeE1qQXlNakkyCk1qZGFGdzB4TmpFeE1Ua3lNakkyTWpkYU1Id3hDekFKQmdOVkJBWVRBbUYzTVE0d0RBWURWUVFJRXdWaGNuVmlZVEVPTUF3R0ExVUUKQ2hNRllYSjFZbUV4RGpBTUJnTlZCQWNUQldGeWRXSmhNUTR3REFZRFZRUUxFd1ZoY25WaVlURU9NQXdHQTFVRUF4TUZZWEoxWW1FeApIVEFiQmdrcWhraUc5dzBCQ1FFV0RtRnlkV0poUUdGeWRXSmhMbUZ5TUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCCmdRREh0QzVnVVh4QktwRXFaVExrTnZGd05Hbk5Ja2dnTk93T1FWTmJwTzBXVkhJaXZpZzVMMzlXcVM5dTBobkErTzdNQ0EvS2xyQVIKNGJYYWVWVmh3ZlVQWUJLSXBhYVRXRlFSNWNUUjFVRlpKTC9PRjl2QWZwT3d6bm9ENjZERENuUVZwYkNqdERZV1greDZpbXhuOEhDWQp4aE1vbDZablRiU3NGVzZWWmpGTWpRSURBUUFCbzRIYU1JSFhNQjBHQTFVZERnUVdCQlR4MGxEempIL2lPQm5PU1FhU0VXUUx4MXN5CkdEQ0Jwd1lEVlIwakJJR2ZNSUdjZ0JUeDBsRHpqSC9pT0JuT1NRYVNFV1FMeDFzeUdLR0JnS1IrTUh3eEN6QUpCZ05WQkFZVEFtRjMKTVE0d0RBWURWUVFJRXdWaGNuVmlZVEVPTUF3R0ExVUVDaE1GWVhKMVltRXhEakFNQmdOVkJBY1RCV0Z5ZFdKaE1RNHdEQVlEVlFRTApFd1ZoY25WaVlURU9NQXdHQTFVRUF4TUZZWEoxWW1FeEhUQWJCZ2txaGtpRzl3MEJDUUVXRG1GeWRXSmhRR0Z5ZFdKaExtRnlnZ0VBCk1Bd0dBMVVkRXdRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFRUJRQURnWUVBWXZCSjBIT1piYkhDbFhtR1VqR3MrR1MreEMxRk8vYW0KMnN1Q1NZcU5COWR5TVhmT1dpSjErVExKaytvL1ladDh2dXhDS2RjWllnbDRsL0w2UHhKOTgyU1JoYzgzWlcyZGtBWkk0TTAvVWQzbwplUGU4NGs4am0zQTdFdkg1d2k1aHZDa0tScHVSQnduM0VpK2pDUm91eFRiektQc3VDVkIrMXNOeXhNVFh6ZjA9PC9kczpYNTA5Q2VydGlmaWNhdGU-PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8-PC9kczpTaWduYXR1cmU-PHNhbWwyOlN1YmplY3Q-PHNhbWwyOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5TYW1sMkJlYXJlckludGVncmF0aW9uVXNlcjwvc2FtbDI6TmFtZUlEPjxzYW1sMjpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI-PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj0iMjAyMy0xMi0xMlQxOTo1NDo1Mi4xNTlaIiBSZWNpcGllbnQ9Imh0dHA6Ly9zZHMxa28ubG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuL2FsaWFzL3NkczFrby5jbG91ZGZvdW5kcnktc2FtbC1sb2dpbiIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q-PHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDIzLTEyLTEyVDE4OjU0OjUyLjEzMloiIE5vdE9uT3JBZnRlcj0iMjAyMy0xMi0xMlQxOTo1NDo1Mi4xNTlaIj48c2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDI6QXVkaWVuY2U-c2RzMWtvLmNsb3VkZm91bmRyeS1zYW1sLWxvZ2luPC9zYW1sMjpBdWRpZW5jZT48L3NhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24-PC9zYW1sMjpDb25kaXRpb25zPjxzYW1sMjpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjMtMTItMTJUMTg6NTQ6NTIuMTI5WiIgU2Vzc2lvbkluZGV4PSJhNDU3NWUyNTBhN2Q1NWMyaGlmM2ZhYWlkaTA0aGEiPjxzYW1sMjpBdXRobkNvbnRleHQ-PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50PjxzYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ-PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJhdXRob3JpdGllcyI-PHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVhYS51c2VyPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48c2FtbDI6QXR0cmlidXRlIE5hbWU9ImVtYWlsIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI-bWFyaXNzYUB0ZXN0aW5nLm9yZzwvc2FtbDI6QXR0cmlidXRlVmFsdWU-PC9zYW1sMjpBdHRyaWJ1dGU-PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJpZCI-PHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPjFmODU5NzVhLTRhYWUtNGEyZS1hOWFhLWYyNmMyZjAwMzBlNDwvc2FtbDI6QXR0cmlidXRlVmFsdWU-PC9zYW1sMjpBdHRyaWJ1dGU-PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJuYW1lIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI-bWFyaXNzYTwvc2FtbDI6QXR0cmlidXRlVmFsdWU-PC9zYW1sMjpBdHRyaWJ1dGU-PHNhbWwyOkF0dHJpYnV0ZSBOYW1lPSJvcmlnaW4iPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj51YWE8L3NhbWwyOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0iem9uZUlkIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI-dWFhPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48L3NhbWwyOkF0dHJpYnV0ZT48L3NhbWwyOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWwyOkFzc2VydGlvbj4";

        //create client in default zone
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.none", "uaa.user,openid", GRANT_TYPE_SAML2_BEARER + ",password,refresh_token", true, TEST_REDIRECT_URI, null, 600, zone.getIdentityZone());


        //String fullPath = "/uaa/oauth/token";
        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(fullPath)
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
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("assertion", assertion)
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet requestParameters = requestParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type"),
                clientSecretParameter,
                clientAssertion,
                clientAssertionType,
                grantTypeParameter.description("The type of token grant requested, in this case `" + GRANT_TYPE_SAML2_BEARER + "`"),
                assertionFormatParameter,
                scopeParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                fieldWithPath("token_type").description("The type of the access token issued, always `bearer`"),
                fieldWithPath("expires_in").description("Number of seconds of lifetime for an access_token, when retrieved"),
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(post)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid"));
    }

    @Test
    void getTokenWithClientAuthInHeader() throws Exception {

        String clientAuthorization = new String(Base64.encodeBase64("app:appclientsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Basic " + clientAuthorization)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        Snippet requestParameters = requestParameters(
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
                parameterWithName("username").required().type(STRING).description("the username for the user trying to get a token"),
                parameterWithName("password").required().type(STRING).description("the password for the user trying to get a token"),
                opaqueFormatParameter
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Base64 encoded client details in the format: `Basic client_id:client_secret`"));

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                idTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, requestHeaders, responseFields));
    }

    @Test
    void getTokenUsingPasscode() throws Exception {
        ScimUser marissa = jdbcScimUserProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", IdentityZoneHolder.get().getId()).get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());
        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal,
                Collections.singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/passcode")
                .accept(APPLICATION_JSON)
                .session(session);

        String passcode = JsonUtils.readValue(
                mockMvc.perform(get)
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(),
                String.class);

        String clientAuthorization = new String(Base64.encodeBase64("app:appclientsecret".getBytes()));

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", "Basic " + clientAuthorization)
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("passcode", passcode)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        Snippet requestParameters = requestParameters(
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
                parameterWithName("passcode").required().type(STRING).description("the one-time passcode for the user which can be retrieved by going to `/passcode`"),
                opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                idTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Base64 encoded client details in the format: `Basic client_id:client_secret`"));
        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, requestHeaders, responseFields))
                .andExpect(status().isOk());
    }

    @Test
    void refreshToken() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_secret", "appclientsecret")
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        MvcResult mvcResult = mockMvc.perform(postForToken).andExpect(status().isOk()).andReturn();
        OAuth2RefreshToken refreshToken = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), CompositeToken.class).getRefreshToken();

        MockHttpServletRequestBuilder postForRefreshToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_secret", "appclientsecret")
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("refresh_token", refreshToken.getValue());

        Snippet requestParameters = requestParameters(
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `refresh_token`"),
                clientIdParameter,
                clientSecretParameter.description("Optional and can be omitted if token before was requested using [PKCE](https://tools.ietf.org/html/rfc7636) with `code_challenge_method=S256` without a secret or client_assertion is used for private_key_jwt client authentication."),
                clientAssertion,
                clientAssertionType,
                parameterWithName("refresh_token").required().type(STRING).description("the refresh_token that was returned along with the access token."),
                opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                idTokenFieldDescriptor,
                refreshTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                jtiFieldDescriptor
        );
        mockMvc.perform(postForRefreshToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields))
                .andExpect(status().isOk())
                .andReturn();
    }

    private void createUser() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", null);
        user = new ScimUser(null, new RandomValueStringGenerator().generate() + "@test.org", "name", "familyName");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = MockMvcUtils.createUser(mockMvc, adminToken, user);
        user.setPassword("secr3T");
    }

    @Test
    void getIdTokenUsingAuthCodeGrant() throws Exception {

        String cfAccessToken = getUserOAuthAccessToken(
                mockMvc,
                "cf",
                "",
                user.getUserName(),
                user.getPassword(),
                "uaa.user"
        );

        String redirect = "http://localhost/redirect/cf";
        MockHttpServletRequestBuilder getAuthCode = get("/oauth/authorize")
                .header("Authorization", "Bearer " + cfAccessToken)
                .param(RESPONSE_TYPE, "code")
                .param(CLIENT_ID, "login")
                .param(REDIRECT_URI, redirect)
                .param(PkceValidationService.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE)
                .param(PkceValidationService.CODE_CHALLENGE_METHOD, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256)
                .param(STATE, new RandomValueStringGenerator().generate());

        MockHttpServletResponse authCodeResponse = mockMvc.perform(getAuthCode)
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
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", code)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, redirect);

        Snippet requestParameters = requestParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).type(STRING).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request")),
                parameterWithName("code").required().type(STRING).description(codeDescription),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
                clientSecretParameter.description("<small><mark>UAA 75.21.0</mark></small> Optional and can be omitted if client has configured allowpublic and [PKCE](https://tools.ietf.org/html/rfc7636) with `code_challenge_method=S256` is used to create to `code`."),
                clientAssertion,
                clientAssertionType,
                codeVerifier,
                opaqueFormatParameter
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                idTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestParameters, responseFields));
    }

    @Test
    void revokeAllTokens_forAUser() throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                "",
                null
        );
        BaseClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "clients.read");


        String userInfoToken = getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                ""
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").description(
                        "Bearer token with one of: " +
                                "`uaa.admin` scope OR " +
                                "`tokens.revoke` scope OR " +
                                "matching `user_id`"),
                IDENTITY_ZONE_ID_HEADER,
                IDENTITY_ZONE_SUBDOMAIN_HEADER
        );
        Snippet pathParameters = pathParameters(parameterWithName("userId").description("The id of the user"));
        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/oauth/token/revoke/user/{userId}", user.getId());


        mockMvc.perform(get
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters));

        mockMvc.perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer " + userInfoToken))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));
    }


    @Test
    void revokeAllTokens_forAUserClientCombination() throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                "",
                null
        );
        BaseClientDetails client = createClient(adminToken, "openid", "password", "");
        BaseClientDetails client2 = createClient(adminToken, "openid", "password", "");


        String userInfoTokenToRevoke = getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "", null, true
        );
        String userInfoTokenToRemainValid = getUserOAuthAccessToken(
                mockMvc,
                client2.getClientId(),
                client2.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "", null, true
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").description(
                        "Bearer token with one of: " +
                                "`uaa.admin` scope OR " +
                                "`tokens.revoke` scope OR " +
                                "(matching `user_id` AND `client_id`)"
                ),
                IDENTITY_ZONE_ID_HEADER,
                IDENTITY_ZONE_SUBDOMAIN_HEADER
        );
        Snippet pathParameters = pathParameters(
                parameterWithName("userId").description("The id of the user"),
                parameterWithName("clientId").description("The id of the client")
        );

        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + userInfoTokenToRevoke))
                .andExpect(status().isOk());


        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/oauth/token/revoke/user/{userId}/client/{clientId}", user.getId(), client.getClientId());

        mockMvc.perform(get
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters));

        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + userInfoTokenToRevoke))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));

        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + userInfoTokenToRemainValid))
                .andExpect(status().isOk());
    }

    @Test
    void revokeAllTokens_forAClient() throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                "",
                null,
                true
        );
        BaseClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "clients.read");
        String readClientsToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        client.getClientId(),
                        client.getClientSecret(),
                        null,
                        null,
                        true
                );
        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").description("Bearer token with `uaa.admin` or `tokens.revoke` scope."),
                IDENTITY_ZONE_ID_HEADER,
                IDENTITY_ZONE_SUBDOMAIN_HEADER
        );
        Snippet pathParameters = pathParameters(parameterWithName("clientId").description("The id of the client"));
        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/oauth/token/revoke/client/{clientId}", client.getClientId());
        mockMvc.perform(get
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters));

        mockMvc.perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer " + readClientsToken))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));
    }

    @Test
    void revokeSingleToken() throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                "",
                null,
                true
        );

        BaseClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "clients.read");


        String userInfoToken = getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "openid",
                IdentityZoneHolder.get(),
                true
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").description(
                        "Bearer token with one of: " +
                                "`uaa.admin` scope OR " +
                                "`tokens.revoke` scope OR " +
                                "the token ID to be revoked"
                ),
                IDENTITY_ZONE_ID_HEADER,
                IDENTITY_ZONE_SUBDOMAIN_HEADER
        );
        Snippet pathParameters = pathParameters(parameterWithName("tokenId").description(
                "The identifier for the token to be revoked. " +
                        "For opaque tokens, use the token itself. " +
                        "For JWT tokens use the `jti` claim in the token."
        ));

        MockHttpServletRequestBuilder delete = RestDocumentationRequestBuilders.delete("/oauth/token/revoke/{tokenId}", userInfoToken);

        mockMvc.perform(delete
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userInfoToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters));
    }

    @Test
    void listTokens_client() throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                "",
                null,
                true
        );

        BaseClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "tokens.list");
        String clientToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                "",
                null,
                true
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName(HttpHeaders.AUTHORIZATION).description("Bearer token containing the `tokens.list` scope."),
                headerWithName(HttpHeaders.ACCEPT).description("Set to " + MediaType.APPLICATION_JSON_VALUE),
                IDENTITY_ZONE_ID_HEADER,
                IDENTITY_ZONE_SUBDOMAIN_HEADER
        );

        Snippet pathParameters = pathParameters(parameterWithName("clientId").description("The client ID to retrieve tokens for"));

        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/oauth/token/list/client/{clientId}", client.getClientId());

        mockMvc.perform(
                get
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + clientToken)
                        .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters, listTokenResponseFields));
    }

    @Test
    void listTokens_user() throws Exception {
        String adminToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                "",
                null,
                true
        );

        BaseClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "tokens.list");
        String clientToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                "",
                null,
                true
        );


        getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "",
                null,
                true
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName(HttpHeaders.AUTHORIZATION).description("Bearer token containing the `tokens.list` scope."),
                headerWithName(HttpHeaders.ACCEPT).description("Set to " + MediaType.APPLICATION_JSON_VALUE),
                IDENTITY_ZONE_ID_HEADER,
                IDENTITY_ZONE_SUBDOMAIN_HEADER
        );

        Snippet pathParameters = pathParameters(parameterWithName("userId").description("The user ID to retrieve tokens for"));

        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/oauth/token/list/user/{userId}", user.getId());

        mockMvc.perform(
                get
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + clientToken)
                        .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, pathParameters, listTokenResponseFields));
    }

    private BaseClientDetails createClient(String token, String scopes, String grantTypes, String authorities) throws Exception {
        BaseClientDetails client = new BaseClientDetails(
                new RandomValueStringGenerator().generate(),
                "",
                scopes,
                grantTypes,
                authorities, "http://redirect.url");
        client.setClientSecret(SECRET);
        BaseClientDetails clientDetails = MockMvcUtils.createClient(mockMvc, token, client);
        clientDetails.setClientSecret(SECRET);
        return clientDetails;
    }
}
