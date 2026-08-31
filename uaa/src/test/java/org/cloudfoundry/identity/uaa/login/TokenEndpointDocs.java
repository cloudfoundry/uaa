package org.cloudfoundry.identity.uaa.login;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
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
import org.cloudfoundry.identity.uaa.zone.ZoneContextPathSessionFilter;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
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
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

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
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestPropertySource(properties = {"login.entityBaseURL=", "uaa.mtls-enabled=true"})
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
    /** Parallel to form body client_id/client_secret: documents client authentication via HTTP Basic (RFC 7617). */
    private static final HeaderDescriptor CLIENT_BASIC_AUTH_HEADER = headerWithName(AUTHORIZATION)
            .description("Base64 encoded client details in the format: `Basic client_id:client_secret`");

    private ScimUser user;

    @Qualifier(SPRING_SECURITY_FILTER_CHAIN)
    @Autowired
    FilterChainProxy securityFilterChain;

    @Qualifier(ZonePathContextRewritingFilter.REGISTRATION_BEAN_NAME)
    @Autowired
    FilterRegistrationBean<ZonePathContextRewritingFilter> zonePathFilterRegistration;

    @Qualifier(ZoneContextPathSessionFilter.REGISTRATION_BEAN_NAME)
    @Autowired
    FilterRegistrationBean<ZoneContextPathSessionFilter> zoneContextPathSessionFilterRegistration;

    /**
     * Registered in {@code SpringServletXmlFiltersConfiguration} but not automatically added to the
     * servlet container by {@code MockMvcBuilders.webAppContextSetup(...)} -- must be added explicitly
     * to the MockMvc filter chain (like the other filters below) so that
     * {@link org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthentication#getCertificateChainFromRequest}
     * can read {@link RawPeerCertificateCaptureFilter#RAW_PEER_CERTIFICATE_ATTRIBUTE} for
     * {@code /oauth/mtls/token} requests.
     */
    @Qualifier("rawPeerCertificateCaptureFilter")
    @Autowired
    FilterRegistrationBean<RawPeerCertificateCaptureFilter> rawPeerCertificateCaptureFilterRegistration;

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
                .addFilter(zonePathFilterRegistration.getFilter())
                .addFilter(zoneContextPathSessionFilterRegistration.getFilter())
                .addFilter(rawPeerCertificateCaptureFilterRegistration.getFilter())
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

    @BeforeEach
    void configureJwksForPrivateKeyJwtDocumentationClients() throws Exception {
        mergeSampleJwtClientConfiguration(IdentityZone.getUaa(), uaaClientDetails("login"));
        mergeSampleJwtClientConfiguration(IdentityZone.getUaa(), uaaClientDetails("app"));
    }

    private UaaClientDetails uaaClientDetails(String clientId) throws Exception {
        return (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId, IdentityZone.getUaa().getId());
    }

    private record AuthCodeResult(String code, String redirect) {
    }

    private AuthCodeResult obtainAuthCodeForLoginClient() throws Exception {
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
        return new AuthCodeResult(location.getQueryParams().getFirst("code"), redirect);
    }

    @Test
    void getTokenUsingAuthCodeGrantWithClientSecret() throws Exception {
        AuthCodeResult auth = obtainAuthCodeForLoginClient();

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_secret", "loginsecret")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", auth.code())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, auth.redirect());

        Snippet formParameters = formParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request"), SnippetUtils.type.value(STRING)),
                parameterWithName("code").description(codeDescription).attributes(SnippetUtils.constraints.value("Required"), SnippetUtils.type.value(STRING)),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
                clientSecretParameter.description("<small><mark>UAA 75.21.0</mark></small> Optional and can be omitted if client has configured allowpublic and [PKCE](https://tools.ietf.org/html/rfc7636) with `code_challenge_method=S256` is used to create to `code`."),
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields));
    }

    @Test
    void getTokenUsingAuthCodeGrantWithAuthorizationHeader() throws Exception {
        AuthCodeResult auth = obtainAuthCodeForLoginClient();

        String clientAuthorization = new String(ENCODER.encode("login:loginsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header(AUTHORIZATION, "Basic " + clientAuthorization)
                .param(CLIENT_ID, "login")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", auth.code())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, auth.redirect());

        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);

        Snippet formParameters = formParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request"), SnippetUtils.type.value(STRING)),
                parameterWithName("code").description(codeDescription).attributes(SnippetUtils.constraints.value("Required"), SnippetUtils.type.value(STRING)),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, formParameters, responseFields));
    }

    @Test
    void getTokenUsingAuthCodeGrantWithClientAssertion() throws Exception {
        AuthCodeResult auth = obtainAuthCodeForLoginClient();

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_assertion", getClientAssertionJwt(IdentityZone.getUaa(), uaaClientDetails("login")))
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", auth.code())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, auth.redirect());

        Snippet formParameters = formParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request"), SnippetUtils.type.value(STRING)),
                parameterWithName("code").description(codeDescription).attributes(SnippetUtils.constraints.value("Required"), SnippetUtils.type.value(STRING)),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields));
    }

    @Test
    void getTokenUsingClientCredentialGrantWithClientSecret() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_secret", "loginsecret")
                .param(SCOPE, "scim.write")
                .param(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        Snippet formParameters = formParameters(
                clientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
                clientSecretParameter,
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
    void getTokenUsingClientCredentialGrantWithClientAssertion() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_assertion", getClientAssertionJwt(IdentityZone.getUaa(), uaaClientDetails("login")))
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(SCOPE, "scim.write")
                .param(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        Snippet formParameters = formParameters(
                clientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
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

        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);

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

    /**
     * Documents {@code /oauth/mtls/token} (RFC 8705 mutual-TLS client authentication, {@code tls_client_auth}).
     * Unlike {@code client_secret}/{@code client_assertion}, this method has no request parameter at all --
     * the client authenticates by presenting an X.509 certificate at the TLS layer itself (or, behind a
     * trusted proxy, via the {@code X-Forwarded-Client-Cert} header), which the Gorouter/servlet container
     * populates on the request before this endpoint's client authentication runs. This test simulates that by
     * setting the standard {@code jakarta.servlet.request.X509Certificate} request attribute directly, which
     * {@link RawPeerCertificateCaptureFilter} (added to the MockMvc filter chain in {@link #setUpContext}, as
     * it would run in the real filter chain) copies into the attribute
     * {@link org.cloudfoundry.identity.uaa.oauth.tls.TlsClientAuthentication#getCertificateChainFromRequest}
     * reads for {@code /oauth/mtls/token/**} requests -- exercising the same
     * {@code ClientDetailsAuthenticationProvider.validateTlsClientAuth} path a genuine mTLS handshake would.
     */
    @Test
    void getTokenUsingClientCredentialGrantWithTlsClientAuth() throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        X500Name caSubject = new X500Name("CN=Test mTLS CA");
        X509Certificate caCert = signCert(caSubject, caSubject, caKeyPair.getPublic(), caKeyPair.getPrivate(), true, BigInteger.valueOf(1));

        KeyPair leafKeyPair = generateKeyPair();
        X500Name leafSubject = new X500Name("CN=mtls-doc-client");
        X509Certificate leafCert = signCert(leafSubject, caSubject, leafKeyPair.getPublic(), caKeyPair.getPrivate(), false, BigInteger.valueOf(2));

        String clientId = "mtlsdocclient" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(),
                Map.of(
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert),
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                        Collections.singletonList(new TlsClientAuthConfiguration.ClaimMapping(
                                "subject_cn", null, "instance_guid"))));
        clientDetailsService.updateClientSecret(clientId, null);
        assertThat(clientDetailsService.loadClientByClientId(clientId).getClientSecret()).isNull();

        MockHttpServletRequestBuilder postForToken = RestDocumentationRequestBuilders.post("/oauth/mtls/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, clientId)
                .param(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                .param(REQUEST_TOKEN_FORMAT, JWT.getStringValue())
                // RawPeerCertificateCaptureFilter.isMtlsTokenPath(...) matches on the *effective*
                // servlet path (post-ZonePathContextRewritingFilter); MockMvc does not compute this
                // itself from the request URI the way a real DispatcherServlet mapping would, so it
                // must be set explicitly here to simulate the real /oauth/mtls/token servlet path.
                .servletPath("/oauth/mtls/token")
                .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{leafCert});

        ParameterDescriptor mtlsClientIdParameter = parameterWithName(CLIENT_ID).required().type(STRING)
                .description("The client ID whose tls-client-auth-ca selects the certificate trust anchor for this mTLS token request.");
        assertThat(mtlsClientIdParameter.getAttributes()).containsEntry("constraints", SnippetUtils.REQUIRED);

        Snippet formParameters = formParameters(
                mtlsClientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
                parameterWithName(REQUEST_TOKEN_FORMAT).optional("jwt").type(STRING)
                        .description("Set to `jwt` to receive a JSON Web Token containing the mTLS certificate-derived claims and RFC 8705 confirmation claim.")
        );

        Snippet responseFields = responseFields(
                accessTokenFieldDescriptor,
                tokenTypeFieldDescriptor,
                expiresInFieldDescriptor,
                scopeFieldDescriptorWhenClientCredentialsToken,
                jtiFieldDescriptor
        );

        MvcResult result = mockMvc.perform(postForToken)
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, responseFields))
                .andReturn();

        Map<String, Object> tokenResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        Jwt accessToken = JwtHelper.decode((String) tokenResponse.get("access_token"));
        String kid = accessToken.getHeader().getKid();
        assertThat(kid).isNotBlank();
        assertThatCode(() -> accessToken.verifySignature(keyInfoService.getKey(kid).getVerifier()))
                .doesNotThrowAnyException();

        Map<String, Object> claims = JsonUtils.readValue(accessToken.getClaims(), Map.class);
        assertThat(claims).containsEntry("instance_guid", "mtls-doc-client");
        String expectedThumbprint = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(leafCert.getEncoded()));
        assertThat((Map<String, Object>) claims.get("cnf"))
                .containsEntry("x5t#S256", expectedThumbprint);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate signCert(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 3_600_000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(signerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        }
        return sw.toString();
    }

    @Test
    void getTokenUsingPasswordGrantWithClientSecret() throws Exception {
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_secret", "appclientsecret")
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("login_hint", "{\"origin\":\"uaa\"}");

        Snippet formParameters = formParameters(
                clientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
                clientSecretParameter,
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
    void getTokenUsingPasswordGrantWithClientAssertion() throws Exception {
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_assertion", getClientAssertionJwt(IdentityZone.getUaa(), uaaClientDetails("app")))
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("login_hint", "{\"origin\":\"uaa\"}");

        Snippet formParameters = formParameters(
                clientIdParameter,
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `password`"),
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

    private record Saml2BearerDocContext(String fullPath, String host, String clientId, String encodedSamlAssertion,
                                         IdentityZone clientZone, UaaClientDetails oauthClient) {
    }

    /**
     * @param useDefaultOAuthTokenPath when {@code true}, the documented HTTP request POSTs to {@code /uaa/oauth/token};
     *                                 the SAML assertion {@code Recipient} must still be the IdP ACS-derived
     *                                 {@code .../oauth/token/alias/&lt;registrationId&gt;} URI (same as the alias-path flow).
     */
    private Saml2BearerDocContext prepareSaml2BearerDocumentationContext(String subdomain, boolean useDefaultOAuthTokenPath) throws Exception {
        final String host = "%s.localhost".formatted(subdomain);
        final String fullPath = useDefaultOAuthTokenPath
                ? "/uaa/oauth/token"
                : "/uaa/oauth/token/alias/%s.integration-saml-entity-id".formatted(subdomain);
        final String origin = "%s.integration-saml-entity-id".formatted(subdomain);
        MockMvcUtils.IdentityZoneCreationResult testZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                subdomain, mockMvc, this.webApplicationContext, null,
                IdentityZoneHolder.getCurrentZoneId());

        IdentityZone samlZone = identityZoneProvisioning.retrieve(testZone.getIdentityZone().getId());

        String samlIssuerEntityId = "%s.cloudfoundry-saml-login".formatted(subdomain);
        String idpMetadata = getIdpMetadata(host, origin, samlIssuerEntityId);
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(
                origin, samlZone.getId(), idpMetadata);
        // Issuer must match entityID in metadata and the SAML assertion; signing uses legacy test keys (issuerEntityId param only).
        idpDef.setIdpEntityId(samlIssuerEntityId);
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setConfig(idpDef);
        provider.setActive(true);
        provider.setIdentityZoneId(samlZone.getId());
        provider.setName(origin);
        provider.setOriginKey(origin);

        IdentityZoneHolder.set(samlZone);
        identityProviderProvisioning.create(provider, samlZone.getId());
        IdentityZoneHolder.clear();

        String spEndpoint = "http://%s:8080/uaa/oauth/token/alias/%s".formatted(host, origin);
        String assertionStr = TestOpenSamlObjects.getEncodedAssertion(samlIssuerEntityId, NameID.UNSPECIFIED,
                "Saml2BearerIntegrationUser", spEndpoint, origin, true);

        String clientId = "testclient" + generator.generate();
        UaaClientDetails oauthClient = setUpClients(clientId, "uaa.none", "uaa.user,openid",
                GRANT_TYPE_SAML2_BEARER + ",password,refresh_token", true,
                TEST_REDIRECT_URI, null, 600, samlZone);
        mergeSampleJwtClientConfiguration(samlZone, oauthClient);
        oauthClient = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId, samlZone.getId());

        return new Saml2BearerDocContext(fullPath, host, clientId, assertionStr, samlZone, oauthClient);
    }

    @Test
    void getTokenUsingSaml2BearerGrantWithClientSecretOnDefaultTokenPath() throws Exception {
        Saml2BearerDocContext ctx = prepareSaml2BearerDocumentationContext("68ues4", true);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(ctx.fullPath())
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(ctx.fullPath());
                    request.setServerName(ctx.host());
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, ctx.host())
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", ctx.clientId())
                .param("client_secret", "secret")
                .param("assertion", ctx.encodedSamlAssertion())
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet formParameters = formParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type"),
                clientSecretParameter,
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

    @Test
    void getTokenUsingSaml2BearerGrantWithAuthorizationHeaderOnDefaultTokenPath() throws Exception {
        Saml2BearerDocContext ctx = prepareSaml2BearerDocumentationContext("68ues5", true);

        String clientAuthorization = new String(ENCODER.encode((ctx.clientId() + ":secret").getBytes()));

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(ctx.fullPath())
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(ctx.fullPath());
                    request.setServerName(ctx.host());
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, ctx.host())
                .header(AUTHORIZATION, "Basic " + clientAuthorization)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", ctx.clientId())
                .param("assertion", ctx.encodedSamlAssertion())
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);
        Snippet formParameters = formParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type"),
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, formParameters, responseFields))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid"));
    }

    @Test
    void getTokenUsingSaml2BearerGrantWithClientAssertionOnDefaultTokenPath() throws Exception {
        Saml2BearerDocContext ctx = prepareSaml2BearerDocumentationContext("68ues6", true);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(ctx.fullPath())
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(ctx.fullPath());
                    request.setServerName(ctx.host());
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, ctx.host())
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", ctx.clientId())
                .param("client_assertion", getClientAssertionJwt(ctx.clientZone(), ctx.oauthClient()))
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("assertion", ctx.encodedSamlAssertion())
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet formParameters = formParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type"),
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

    @Test
    void getTokenUsingSaml2BearerGrantWithClientSecret() throws Exception {
        Saml2BearerDocContext ctx = prepareSaml2BearerDocumentationContext("68ues1", false);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(ctx.fullPath())
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(ctx.fullPath());
                    request.setServerName(ctx.host());
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, ctx.host())
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", ctx.clientId())
                .param("client_secret", "secret")
                .param("assertion", ctx.encodedSamlAssertion())
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet formParameters = formParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type"),
                clientSecretParameter,
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

    @Test
    void getTokenUsingSaml2BearerGrantWithAuthorizationHeader() throws Exception {
        Saml2BearerDocContext ctx = prepareSaml2BearerDocumentationContext("68ues3", false);

        String clientAuthorization = new String(ENCODER.encode((ctx.clientId() + ":secret").getBytes()));

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(ctx.fullPath())
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(ctx.fullPath());
                    request.setServerName(ctx.host());
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, ctx.host())
                .header(AUTHORIZATION, "Basic " + clientAuthorization)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", ctx.clientId())
                .param("assertion", ctx.encodedSamlAssertion())
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);
        Snippet formParameters = formParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type"),
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, formParameters, responseFields))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.scope").value("openid"));
    }

    @Test
    void getTokenUsingSaml2BearerGrantWithClientAssertion() throws Exception {
        Saml2BearerDocContext ctx = prepareSaml2BearerDocumentationContext("68ues2", false);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post(ctx.fullPath())
                .with(request -> {
                    request.setServerPort(8080);
                    request.setRequestURI(ctx.fullPath());
                    request.setServerName(ctx.host());
                    return request;
                })
                .contextPath("/uaa")
                .accept(APPLICATION_JSON)
                .header(HOST, ctx.host())
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("grant_type", TokenConstants.GRANT_TYPE_SAML2_BEARER)
                .param("client_id", ctx.clientId())
                .param("client_assertion", getClientAssertionJwt(ctx.clientZone(), ctx.oauthClient()))
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("assertion", ctx.encodedSamlAssertion())
                .param("scope", "openid");

        final ParameterDescriptor assertionFormatParameter = parameterWithName("assertion").required().type(STRING).description("An XML based SAML 2.0 bearer assertion, which is Base64URl encoded.");
        Snippet formParameters = formParameters(
                clientIdParameter.description("The client ID of the receiving client, this client must have `urn:ietf:params:oauth:grant-type:saml2-bearer` grant type"),
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

    /**
     * Mock IdP metadata. {@code host} and {@code origin} drive SSO locations; {@code idpEntityId} must match
     * the SAML assertion issuer and {@link SamlIdentityProviderDefinition#setIdpEntityId}. Unsigned metadata
     * (no {@code ds:Signature}) so {@code idpEntityId} can vary per subdomain; {@code createLocalSamlIdpDefinition}
     * sets {@code metadataTrustCheck} false.
     */
    private static String getIdpMetadata(String host, String origin, String idpEntityId) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="%2$s"
                                     entityID="%3$s">
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
                </md:EntityDescriptor>""".formatted(host, origin, idpEntityId);
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

        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);

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
        MockMvcUtils.getZoneSession(session).setAttribute(
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

        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);
        mockMvc.perform(postForToken)
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), formParameters, requestHeaders, responseFields))
                .andExpect(status().isOk());
    }

    @Test
    void refreshTokenWithClientSecret() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_secret", "appclientsecret")
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
                .param(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("refresh_token", refreshToken.getValue());

        Snippet formParameters = formParameters(
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `refresh_token`"),
                clientIdParameter,
                clientSecretParameter.description("Optional and can be omitted if token before was requested using [PKCE](https://tools.ietf.org/html/rfc7636) with `code_challenge_method=S256` without a secret or client_assertion is used for private_key_jwt client authentication."),
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

    @Test
    void refreshTokenWithAuthorizationHeader() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_secret", "appclientsecret")
                .param(GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        MvcResult mvcResult = mockMvc.perform(postForToken).andExpect(status().isOk()).andReturn();
        OAuth2RefreshToken refreshToken = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), CompositeToken.class).getRefreshToken();

        String clientAuthorization = new String(ENCODER.encode("app:appclientsecret".getBytes()));
        MockHttpServletRequestBuilder postForRefreshToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header(AUTHORIZATION, "Basic " + clientAuthorization)
                .param(CLIENT_ID, "app")
                .param(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("refresh_token", refreshToken.getValue());

        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);

        Snippet formParameters = formParameters(
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `refresh_token`"),
                clientIdParameter,
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, formParameters, responseFields))
                .andExpect(status().isOk())
                .andReturn();
    }

    @Test
    void refreshTokenWithClientAssertion() throws Exception {

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "app")
                .param("client_assertion", getClientAssertionJwt(IdentityZone.getUaa(), uaaClientDetails("app")))
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
                .param("client_assertion", getClientAssertionJwt(IdentityZone.getUaa(), uaaClientDetails("app")))
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN)
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("refresh_token", refreshToken.getValue());

        Snippet formParameters = formParameters(
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `refresh_token`"),
                clientIdParameter,
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
    void getIdTokenUsingAuthCodeGrantWithClientSecret() throws Exception {
        AuthCodeResult auth = obtainAuthCodeForLoginClient();

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_secret", "loginsecret")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", auth.code())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, auth.redirect());

        Snippet formParameters = formParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).type(STRING).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request")),
                parameterWithName("code").required().type(STRING).description(codeDescription),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
                clientSecretParameter.description("<small><mark>UAA 75.21.0</mark></small> Optional and can be omitted if client has configured allowpublic and [PKCE](https://tools.ietf.org/html/rfc7636) with `code_challenge_method=S256` is used to create to `code`."),
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
    void getIdTokenUsingAuthCodeGrantWithAuthorizationHeader() throws Exception {
        AuthCodeResult auth = obtainAuthCodeForLoginClient();

        String clientAuthorization = new String(ENCODER.encode("login:loginsecret".getBytes()));
        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header(AUTHORIZATION, "Basic " + clientAuthorization)
                .param(CLIENT_ID, "login")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", auth.code())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, auth.redirect());

        Snippet requestHeaders = requestHeaders(CLIENT_BASIC_AUTH_HEADER);

        Snippet formParameters = formParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).type(STRING).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request")),
                parameterWithName("code").required().type(STRING).description(codeDescription),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
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
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, formParameters, responseFields));
    }

    @Test
    void getIdTokenUsingAuthCodeGrantWithClientAssertion() throws Exception {
        AuthCodeResult auth = obtainAuthCodeForLoginClient();

        MockHttpServletRequestBuilder postForToken = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param(CLIENT_ID, "login")
                .param("client_assertion", getClientAssertionJwt(IdentityZone.getUaa(), uaaClientDetails("login")))
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE)
                .param("code", auth.code())
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param(PkceValidationService.CODE_VERIFIER, UaaTestAccounts.CODE_VERIFIER)
                .param(REDIRECT_URI, auth.redirect());

        Snippet formParameters = formParameters(
                clientIdParameter,
                parameterWithName(REDIRECT_URI).type(STRING).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)").attributes(SnippetUtils.constraints.value("Required if provided on authorization request")),
                parameterWithName("code").required().type(STRING).description(codeDescription),
                grantTypeParameter.description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
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

        MvcResult revokedResult = mockMvc.perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer " + userInfoToken))
                .andExpect(status().isUnauthorized())
                .andReturn();
        assertThat(revokedResult.getResponse().getContentAsString()).contains("\"error\":\"invalid_token\"");
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

        MvcResult revokedResult = mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + userInfoTokenToRevoke))
                .andExpect(status().isUnauthorized())
                .andReturn();
        assertThat(revokedResult.getResponse().getContentAsString()).contains("\"error\":\"invalid_token\"");

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

        MvcResult revokedResult = mockMvc.perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer " + readClientsToken))
                .andExpect(status().isUnauthorized())
                .andReturn();
        assertThat(revokedResult.getResponse().getContentAsString()).contains("\"error\":\"invalid_token\"");
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
