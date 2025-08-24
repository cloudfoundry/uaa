package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.REDIRECT_URI;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.SCOPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.STATE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT_NONE;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.headers.HeaderDocumentation.responseHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthorizeEndpointDocs extends EndpointDocs {
    private final ParameterDescriptor clientIdParameter = parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client").attributes(key("constraints").value("Required"), key("type").value(STRING));
    private final ParameterDescriptor scopesParameter = parameterWithName(SCOPE).description("requested scopes, space-delimited").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor redirectParameter = parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied), optional if pre-registered by the client").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor promptParameter = parameterWithName(ID_TOKEN_HINT_PROMPT).description("specifies whether to prompt for user authentication. Only value `" + ID_TOKEN_HINT_PROMPT_NONE + "` is supported.").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor responseTypeParameter = parameterWithName(RESPONSE_TYPE).attributes(key("constraints").value("Required"), key("type").value(STRING));
    private final ParameterDescriptor loginHintParameter = parameterWithName("login_hint").optional(null).type(STRING).description("<small><mark>UAA 4.19.0</mark></small> Indicates the identity provider to be used. The passed string has to be a URL-Encoded JSON Object, containing the field `origin` with value as `origin_key` of an identity provider.");
    private final ParameterDescriptor codeChallenge = parameterWithName(PkceValidationService.CODE_CHALLENGE).description("<small><mark>UAA 75.5.0</mark></small> [PKCE](https://tools.ietf.org/html/rfc7636) Code Challenge. When `code_challenge` is present also a `code_challenge_method` must be provided. A matching `code_verifier` parameter must be provided in the subsequent request to get an `access_token` from `/oauth/token`").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor codeChallengeMethod = parameterWithName(PkceValidationService.CODE_CHALLENGE_METHOD).description("<small><mark>UAA 75.5.0</mark></small> [PKCE](https://tools.ietf.org/html/rfc7636) Code Challenge Method. `S256` and `plain` methods are supported. `S256` method creates a BASE64 URL encoded SHA256 hash of the `code_verifier`. The `plain` method is intended for constrained devices unable to calculate SHA256. In this case the `code_verifier` equals the `code_challenge`. If possible it is recommended to use `S256`.").attributes(key("constraints").value("Optional"), key("type").value(STRING));

    private UaaAuthentication principal;

    @Autowired
    private JdbcScimUserProvisioning userProvisioning;

    @BeforeEach
    void setUp() {
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", IdentityZoneHolder.get().getId()).getFirst();
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());
        principal = new UaaAuthentication(uaaPrincipal, Collections.singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);
    }

    @Test
    void browserCodeRequest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockMvcUtils.MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(APPLICATION_FORM_URLENCODED)
                .param(RESPONSE_TYPE, "code")
                .param(CLIENT_ID, "login")
                .param(SCOPE, "openid oauth.approvals")
                .param(REDIRECT_URI, "http://localhost/app")
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8))
                .param(PkceValidationService.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE)
                .param(PkceValidationService.CODE_CHALLENGE_METHOD, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256)
                .session(session);

        Snippet queryParameters = queryParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `code` for requesting an authorization code for an access token, as per OAuth spec"),
                clientIdParameter,
                scopesParameter,
                redirectParameter,
                codeChallenge,
                codeChallengeMethod,
                loginHintParameter
        );

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        queryParameters));
    }

    @Test
    void apiCodeRequest() throws Exception {
        resetMarissaPassword(userProvisioning);

        String cfAccessToken = MockMvcUtils.getUserOAuthAccessToken(
                mockMvc,
                "cf",
                "",
                UaaTestAccounts.DEFAULT_USERNAME,
                UaaTestAccounts.DEFAULT_PASSWORD,
                "uaa.user"
        );

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .header("Authorization", "Bearer " + cfAccessToken)
                .param(RESPONSE_TYPE, "code")
                .param(CLIENT_ID, "login")
                .param(REDIRECT_URI, "http://localhost/redirect/cf")
                .param(PkceValidationService.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE)
                .param(PkceValidationService.CODE_CHALLENGE_METHOD, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256)
                .param(STATE, new AlphanumericRandomValueStringGenerator().generate());

        Snippet queryParameters = queryParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `code` for requesting an authorization code for an access token, as per OAuth spec"),
                clientIdParameter,
                redirectParameter,
                codeChallenge,
                codeChallengeMethod,
                parameterWithName(STATE).description("any random string to be returned in the Location header as a query parameter, used to achieve per-request customization").attributes(key("constraints").value("Required"), key("type").value(STRING))
        );

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        queryParameters,
                        requestHeaders(headerWithName("Authorization").description("Bearer token containing uaa.user scope - the authentication for this user"))));
    }

    @Test
    void implicitGrant_browserRequest() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockMvcUtils.MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(APPLICATION_FORM_URLENCODED)
                .param(RESPONSE_TYPE, "token")
                .param(CLIENT_ID, "app")
                .param(SCOPE, "openid")
                .param(REDIRECT_URI, "http://localhost:8080/app/")
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8))
                .session(session);

        Snippet queryParameters = queryParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `token`, i.e. an access token"),
                clientIdParameter,
                scopesParameter,
                redirectParameter,
                loginHintParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes access_token in the reply fragment if successful"));

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        responseHeaders,
                        queryParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        assertThat(location).contains("access_token=");
    }

    @Test
    void implicitGrantWithPromptParameter_browserRequest() throws Exception {

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(APPLICATION_FORM_URLENCODED)
                .param(RESPONSE_TYPE, "token")
                .param(CLIENT_ID, "app")
                .param(SCOPE, "openid")
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE)
                .param(REDIRECT_URI, "http://localhost:8080/app/");

        Snippet queryParameters = queryParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `token`, i.e. an access token"),
                clientIdParameter,
                scopesParameter,
                redirectParameter,
                promptParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Redirect url specified in the request parameters."));

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        responseHeaders,
                        queryParameters)).andReturn();
    }

    @Test
    void getIdToken() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockMvcUtils.MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(APPLICATION_FORM_URLENCODED)
                .param(RESPONSE_TYPE, "id_token")
                .param(CLIENT_ID, "app")
                .param(SCOPE, "openid")
                .param(REDIRECT_URI, "http://localhost:8080/app/")
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8))
                .session(session);

        Snippet queryParameters = queryParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `id_token`"),
                clientIdParameter,
                scopesParameter,
                redirectParameter,
                loginHintParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes id_token in the reply fragment if successful"));

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(print())
                .andDo(document("{ClassName}/{methodName}",
                        responseHeaders,
                        queryParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        assertThat(location).contains("id_token=");
    }

    @Test
    void getIdTokenAndAccessToken() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockMvcUtils.MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(APPLICATION_FORM_URLENCODED)
                .param(RESPONSE_TYPE, "token id_token")
                .param(CLIENT_ID, "app")
                .param(SCOPE, "openid")
                .param(REDIRECT_URI, "http://localhost:8080/app/")
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8))
                .session(session);

        Snippet queryParameters = queryParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `token id_token`, indicating both an access token and an ID token."),
                clientIdParameter,
                scopesParameter,
                redirectParameter,
                loginHintParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes access_token and id_token in the reply fragment if successful"));

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(print())
                .andDo(document("{ClassName}/{methodName}",
                        responseHeaders,
                        queryParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        assertThat(location).contains("id_token=")
                .contains("access_token=");
    }

    @Test
    void getIdTokenAndCode() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockMvcUtils.MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(APPLICATION_FORM_URLENCODED)
                .param(RESPONSE_TYPE, "code id_token")
                .param(CLIENT_ID, "app")
                .param(SCOPE, "openid")
                .param(REDIRECT_URI, "http://localhost:8080/app/")
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8))
                .session(session);

        Snippet queryParameters = queryParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `id_token code`, indicating a request for an ID token and an authorization code."),
                clientIdParameter,
                scopesParameter,
                redirectParameter,
                loginHintParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes code and id_token in the reply fragment if successful"));

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(print())
                .andDo(document("{ClassName}/{methodName}",
                        responseHeaders,
                        queryParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        assertThat(location).contains("id_token=")
                .contains("code=");
    }

    private static void resetMarissaPassword(ScimUserProvisioning scimUserProvisioning) {
        ScimUser marissa = scimUserProvisioning.query("username eq \"marissa\"", IdentityZoneHolder.get().getId()).getFirst();

        scimUserProvisioning.changePassword(
                marissa.getId(),
                null,
                UaaTestAccounts.DEFAULT_PASSWORD,
                IdentityZoneHolder.get().getId());
    }
}
