package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.ManualRestDocumentation;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.net.URLEncoder;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT_NONE;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.restdocs.headers.HeaderDocumentation.*;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
@Transactional
public class AuthorizeEndpointDocs {
    private final ParameterDescriptor clientIdParameter = parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client").attributes(key("constraints").value("Required"), key("type").value(STRING));
    private final ParameterDescriptor scopesParameter = parameterWithName(SCOPE).description("requested scopes, space-delimited").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor redirectParameter = parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied), optional if pre-registered by the client").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor promptParameter = parameterWithName(ID_TOKEN_HINT_PROMPT).description("specifies whether to prompt for user authentication. Only value `" + ID_TOKEN_HINT_PROMPT_NONE + "` is supported.").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor responseTypeParameter = parameterWithName(RESPONSE_TYPE).attributes(key("constraints").value("Required"), key("type").value(STRING));
    private final ParameterDescriptor loginHintParameter = parameterWithName("login_hint").optional(null).type(STRING).description("<small><mark>UAA 4.19.0</mark></small> Indicates the identity provider to be used. The passed string has to be a URL-Encoded JSON Object, containing the field `origin` with value as `origin_key` of an identity provider.");

    private UaaAuthentication principal;
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private JdbcScimUserProvisioning userProvisioning;
    @Autowired
    private FilterChainProxy springSecurityFilterChain;

    private ManualRestDocumentation restDocumentation = new ManualRestDocumentation("build/generated-snippets");

    @BeforeEach
    public void setUp(TestInfo testInfo) throws Exception {
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", IdentityZoneHolder.get().getId()).get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());
        principal = new UaaAuthentication(uaaPrincipal, Collections.singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);

        restDocumentation.beforeTest(testInfo.getTestClass().get(), testInfo.getDisplayName());
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .apply(documentationConfiguration(restDocumentation)
                        .uris().withPort(80)
                        .and()
                        .snippets()
                        .withTemplateFormat(markdown()))
                .build();
    }

    @AfterEach
    public void teardownRestDocumentationContext() {
        restDocumentation.afterTest();
    }

    @Test
    public void browserCodeRequest() throws Exception {
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
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8"))
                .session(session);

        Snippet requestParameters = requestParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `code` for requesting an authorization code for an access token, as per OAuth spec"),
                clientIdParameter,
                scopesParameter,
                redirectParameter,
                loginHintParameter
        );

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        requestParameters));
    }

    @Test
    public void apiCodeRequest() throws Exception {
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
                .param(STATE, new RandomValueStringGenerator().generate());

        Snippet requestParameters = requestParameters(
                responseTypeParameter.description("Space-delimited list of response types. Here, `code` for requesting an authorization code for an access token, as per OAuth spec"),
                clientIdParameter,
                redirectParameter,
                parameterWithName(STATE).description("any random string to be returned in the Location header as a query parameter, used to achieve per-request customization").attributes(key("constraints").value("Required"), key("type").value(STRING))
        );

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        requestParameters).snippets(requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing uaa.user scope - the authentication for this user"))));
    }

    @Test
    public void implicitGrant_browserRequest() throws Exception {
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
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8"))
                .session(session);

        Snippet requestParameters = requestParameters(
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
                        requestParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Assert.assertThat(location, containsString("access_token="));
    }

    @Test
    public void implicitGrantWithPromptParameter_browserRequest() throws Exception {

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(APPLICATION_FORM_URLENCODED)
                .param(RESPONSE_TYPE, "token")
                .param(CLIENT_ID, "app")
                .param(SCOPE, "openid")
                .param(ID_TOKEN_HINT_PROMPT, ID_TOKEN_HINT_PROMPT_NONE)
                .param(REDIRECT_URI, "http://localhost:8080/app/");

        Snippet requestParameters = requestParameters(
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
                        requestParameters)).andReturn();
    }

    @Test
    public void getIdToken() throws Exception {
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
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8"))
                .session(session);

        Snippet requestParameters = requestParameters(
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
                        requestParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Assert.assertThat(location, containsString("id_token="));
    }

    @Test
    public void getIdTokenAndAccessToken() throws Exception {
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
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8"))
                .session(session);

        Snippet requestParameters = requestParameters(
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
                        requestParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Assert.assertThat(location, containsString("id_token="));
        Assert.assertThat(location, containsString("access_token="));
    }

    @Test
    public void getIdTokenAndCode() throws Exception {
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
                .param("login_hint", URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8"))
                .session(session);

        Snippet requestParameters = requestParameters(
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
                        requestParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Assert.assertThat(location, containsString("id_token="));
        Assert.assertThat(location, containsString("code="));
    }

    private static void resetMarissaPassword(ScimUserProvisioning scimUserProvisioning) {
        ScimUser marissa = scimUserProvisioning.query("username eq \"marissa\"", IdentityZoneHolder.get().getId()).get(0);

        scimUserProvisioning.changePassword(
                marissa.getId(),
                null,
                UaaTestAccounts.DEFAULT_PASSWORD,
                IdentityZoneHolder.get().getId());
    }
}
