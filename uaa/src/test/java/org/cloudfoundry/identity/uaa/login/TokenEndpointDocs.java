package org.cloudfoundry.identity.uaa.login;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.TestOpenSamlObjects;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.JUnitRestDocumentationExtension;
import org.cloudfoundry.identity.uaa.test.SnippetUtils;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.saml.saml2.core.NameID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.MockSecurityContext;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.REDIRECT_URI;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.STATE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyCertificate;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyKey;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyPassphrase;
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
import static org.springframework.restdocs.request.RequestDocumentation.formParameters;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(JUnitRestDocumentationExtension.class)
class TokenEndpointDocs extends AbstractTokenMockMvcTests {
    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private final ParameterDescriptor grantTypeParameter = parameterWithName(GRANT_TYPE).required().type(STRING).description("OAuth 2 grant type");

    private final ParameterDescriptor clientIdParameter = parameterWithName(CLIENT_ID).optional(null).type(STRING).description("A unique string representing the registration information provided by the client, the recipient of the token. Optional if it is passed as part of the Basic Authorization header or as part of the client_assertion.");
    private final ParameterDescriptor clientSecretParameter = parameterWithName("client_secret").optional(null).type(STRING).description("The [secret passphrase configured](#change-secret) for the OAuth client. Optional if it is passed as part of the Basic Authorization header or if client_assertion is sent as part of private_key_jwt authentication.");
    private final ParameterDescriptor opaqueFormatParameter = parameterWithName(REQUEST_TOKEN_FORMAT).optional("jwt").type(STRING).description("Can be set to `" + OPAQUE.getStringValue() + "` to retrieve an opaque token or to `" + JWT.getStringValue() + "` to retrieve a JWT token. Please refer to the Revoke Tokens endpoint doc for information about the revocability of opaque vs. jwt tokens.");
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

    private final Snippet listTokenResponseFields = responseFields(
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

    @Qualifier(SPRING_SECURITY_FILTER_CHAIN)
    @Autowired
    FilterChainProxy securityFilterChain;

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    void beforeEach() {
        IdentityZone.getUaa().getConfig().getSamlConfig().setPrivateKey(legacyKey());
        IdentityZone.getUaa().getConfig().getSamlConfig().setPrivateKeyPassword(legacyPassphrase());
        IdentityZone.getUaa().getConfig().getSamlConfig().setCertificate(legacyCertificate());
    }

    @BeforeEach
    void setUpContext(ManualRestDocumentation manualRestDocumentation) {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(securityFilterChain)
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
                .param(STATE, new AlphanumericRandomValueStringGenerator().generate());

        MockHttpServletResponse authCodeResponse = mockMvc.perform(getAuthCode)
                .andExpect(status().isFound())
                .andReturn()
                .getResponse();

        UriComponents location = UriComponentsBuilder.fromUri(URI.create(authCodeResponse.getHeader("Location"))).build();
        String code = location.getQueryParams().getFirst("code");

        String clientAuthBase64 = new String(ENCODER.encode(("login:loginsecret".getBytes())));
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

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), headerFields, formParameters, responseFields));
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

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields));
    }

    @Test
    void getTokenUsingClientCredentialGrantWithAuthorizationHeader() throws Exception {

        String clientAuthorization = new String(ENCODER.encode("login:loginsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                .param(SCOPE, "scim.write")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .header("Authorization", "Basic " + clientAuthorization);

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, requestHeaders, responseFields));
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

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields));
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

        Snippet formParameters = formParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `refresh_token` grant type"),
                grantTypeParameter.description("The type of token grant requested, in this case `" + GRANT_TYPE_USER_TOKEN + "`"),
                opaqueFormatParameter.description("This parameter is ignored. The refresh_token will always be opaque"),
                scopeParameter
        );

        Snippet responseFields = responseFields(
                fieldWithPath("access_token").description("This field is always `null`."),
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenUserToken,
                refreshTokenFieldDescriptor,
                jtiFieldDescriptor
        );

        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, formParameters, responseFields));
    }

    @Test
    void getTokenUsingSaml2BearerGrant() throws Exception {
        final String subdomain = "68uexx";
        // all our SAML defaults use `:8080/uaa/` so we have to use that here too
        final String host = "%s.localhost".formatted(subdomain);
        final String fullPath = "/uaa/oauth/token/alias/%s.integration-saml-entity-id".formatted(subdomain);
        final String origin = "%s.integration-saml-entity-id".formatted(subdomain);
        MockMvcUtils.IdentityZoneCreationResult testZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                subdomain, mockMvc, this.webApplicationContext, null,
                IdentityZoneHolder.getCurrentZoneId());

        //create an IDP in the default zone
        String idpMetadata = getIdpMetadata(host, origin);
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(
                origin, testZone.getIdentityZone().getId(), idpMetadata);
        idpDef.setIdpEntityId("68uexx.cloudfoundry-saml-login");
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(testZone.getIdentityZone().getId());
        provider.setName(origin);
        provider.setOriginKey(origin);

        IdentityZoneHolder.set(testZone.getIdentityZone());
        identityProviderProvisioning.create(provider, testZone.getIdentityZone().getId());
        IdentityZoneHolder.clear();

        String spEndpoint = "http://%s:8080/uaa/oauth/token/alias/%s".formatted(host, origin);
        String assertionStr = TestOpenSamlObjects.getEncodedAssertion("68uexx.cloudfoundry-saml-login", NameID.UNSPECIFIED,
                "Saml2BearerIntegrationUser", spEndpoint, origin, true);

        // create a client in the default zone
        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, "uaa.none", "uaa.user,openid",
                GRANT_TYPE_SAML2_BEARER + ",password,refresh_token", true,
                TEST_REDIRECT_URI, null, 600, testZone.getIdentityZone());

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
                .param("assertion", assertionStr)
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid"));
    }

    private static String getIdpMetadata(String host, String origin) {
        //Mock an IDP metadata: %1$s is the host; %2$s is the origin
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="%2$s"
                                     entityID="68uexx.cloudfoundry-saml-login">
                    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:SignedInfo>
                            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                            <ds:Reference URI="#%2$s">
                                <ds:Transforms>
                                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                                </ds:Transforms>
                                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                                <ds:DigestValue>MNO5mOgijKliauTLhxL1pqT15s4=</ds:DigestValue>
                            </ds:Reference>
                        </ds:SignedInfo>
                        <ds:SignatureValue>
                            CwxB189hOth7P4g+jswYiG1XHyy0a8Pci6LahimDi0sSuWF5ui1Dw8MSamNDfi2GC5QGArrupPdxgX5F8BFFuio3XkmcQqRhsC01R2u1/NhpabGTgczrk1LYMpCaIOitaXRM2cEkqrmf/s6S3zXDQkQJTcJefc/0NrYgFN6Pisc=
                        </ds:SignatureValue>
                        <ds:KeyInfo>
                            <ds:X509Data>
                                <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF
                                    YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM
                                    BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2
                                    MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE
                                    ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx
                                    HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
                                    gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR
                                    4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY
                                    xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy
                                    GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3
                                    MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL
                                    EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA
                                    MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am
                                    2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o
                                    ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=
                                </ds:X509Certificate>
                            </ds:X509Data>
                        </ds:KeyInfo>
                    </ds:Signature>
                    <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                                         protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:KeyDescriptor use="signing">
                            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                                <ds:X509Data>
                                    <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF
                                        YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM
                                        BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2
                                        MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE
                                        ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx
                                        HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
                                        gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR
                                        4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY
                                        xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy
                                        GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3
                                        MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL
                                        EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA
                                        MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am
                                        2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o
                                        ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=
                                    </ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>
                        </md:KeyDescriptor>
                        <md:KeyDescriptor use="encryption">
                            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                                <ds:X509Data>
                                    <ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF
                                        YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM
                                        BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2
                                        MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE
                                        ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx
                                        HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
                                        gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR
                                        4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY
                                        xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy
                                        GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3
                                        MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL
                                        EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA
                                        MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am
                                        2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o
                                        ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=
                                    </ds:X509Certificate>
                                </ds:X509Data>
                            </ds:KeyInfo>
                        </md:KeyDescriptor>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                                Location="http://%1$s:8080/uaa/saml/idp/SSO/alias/%2$s"/>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                                Location="http://%1$s:8080/uaa/saml/idp/SSO/alias/%2$s"/>
                    </md:IDPSSODescriptor>
                </md:EntityDescriptor>""".formatted(host, origin);
    }

    @Test
    void getTokenWithClientAuthInHeader() throws Exception {

        String clientAuthorization = new String(ENCODER.encode("app:appclientsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Basic " + clientAuthorization)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, requestHeaders, responseFields));
    }

    @Test
    void getTokenUsingPasscode() throws Exception {
        ScimUser marissa = jdbcScimUserProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", IdentityZoneHolder.get().getId()).getFirst();
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

        String clientAuthorization = new String(ENCODER.encode("app:appclientsecret".getBytes()));

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", "Basic " + clientAuthorization)
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("passcode", passcode)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, requestHeaders, responseFields))
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

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields))
                .andExpect(status().isOk())
                .andReturn();
    }

    private void createUser() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", null);
        user = new ScimUser(null, new AlphanumericRandomValueStringGenerator().generate() + "@test.org", "name", "familyName");
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
                .param(STATE, new AlphanumericRandomValueStringGenerator().generate());

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

        Snippet formParameters = formParameters(
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields));
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
        UaaClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "clients.read");

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
        UaaClientDetails client = createClient(adminToken, "openid", "password", "");
        UaaClientDetails client2 = createClient(adminToken, "openid", "password", "");

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
        UaaClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "clients.read");
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

        UaaClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "clients.read");

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

        UaaClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "tokens.list");
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

        UaaClientDetails client = createClient(adminToken, "openid", "client_credentials,password", "tokens.list");
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

    private UaaClientDetails createClient(String token, String scopes, String grantTypes, String authorities) throws Exception {
        UaaClientDetails client = new UaaClientDetails(
                new AlphanumericRandomValueStringGenerator().generate(),
                "",
                scopes,
                grantTypes,
                authorities, "http://redirect.url");
        client.setClientSecret(SECRET);
        UaaClientDetails clientDetails = MockMvcUtils.createClient(mockMvc, token, client);
        clientDetails.setClientSecret(SECRET);
        return clientDetails;
    }
}
