package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ID_TOKEN_HINT_PROMPT_NONE;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.headers.HeaderDocumentation.responseHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.SCOPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.STATE;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuthorizeEndpointDocs extends InjectedMockContextTest {
    private final ParameterDescriptor clientIdParameter = parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client").attributes(key("constraints").value("Required"), key("type").value(STRING));
    private final ParameterDescriptor scopesParameter = parameterWithName(SCOPE).description("requested scopes, space-delimited").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor redirectParameter = parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied), optional if pre-registered by the client").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor promptParameter = parameterWithName(ID_TOKEN_HINT_PROMPT).description("specifies whether to prompt for user authentication. Only value `"+ID_TOKEN_HINT_PROMPT_NONE+"` is supported.").attributes(key("constraints").value("Optional"), key("type").value(STRING));
    private final ParameterDescriptor responseTypeParameter = parameterWithName(RESPONSE_TYPE).attributes(key("constraints").value("Required"), key("type").value(STRING));

    private UsernamePasswordAuthenticationToken principal;

    @Before
    public void setUp() throws Exception {
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"").get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());
        principal = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, Arrays.asList(UaaAuthority.fromAuthorities("uaa.user")));
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
            .session(session);

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("either `code` for requesting an authorization code for an access token, as per OAuth spec"),
            clientIdParameter,
            scopesParameter,
            redirectParameter
        );

        getMockMvc().perform(get)
            .andExpect(status().isFound())
            .andDo(document("{ClassName}/{methodName}",
                requestParameters));
    }

    @Test
    @Ignore
    public void jsonCodeRequestUnapproved() throws Exception {
        MockHttpSession session = new MockHttpSession();
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(principal);
        session.putValue("SPRING_SECURITY_CONTEXT", securityContext);

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
            .accept(APPLICATION_JSON)
            .param(RESPONSE_TYPE, "code")
            .param(CLIENT_ID, "dashboard")
            .param(SCOPE, "dashboard.user openid")
            .param(REDIRECT_URI, "http://redirect.to/app")
            .session(session);

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("\"code\" for requesting an authorization code or \"token\" for an access token, as per OAuth spec"),
            clientIdParameter,
            scopesParameter,
            redirectParameter
        );

        Snippet responseFields = responseFields(
            fieldWithPath("message").description("an explanation of the failed outcome"),
            fieldWithPath("scopes").description("a list of scopes that need to be approved or denied")
        );

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andDo(print())
            .andExpect(content().string(not(isEmptyOrNullString())))
            .andDo(document("{ClassName}/{methodName}",
                requestParameters,
                responseFields));
    }

    @Test
    public void apiCodeRequest() throws Exception {
        String cfAccessToken = utils().getUserOAuthAccessToken(
            getMockMvc(),
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
            responseTypeParameter.description("`code` for requesting an authorization code for an access token, as per OAuth spec"),
            clientIdParameter,
            redirectParameter,
            parameterWithName(STATE).description("any random string to be returned in the Location header as a query parameter, used to achieve per-request customization").attributes(key("constraints").value("Required"), key("type").value(STRING))
        );

        getMockMvc().perform(get)
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
            .session(session);

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("Expected response type, in this case \"token\", i.e. an access token"),
            clientIdParameter,
            scopesParameter,
            redirectParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes access_token in the reply fragment if successful"));

        MvcResult mvcResult = getMockMvc().perform(get)
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
          responseTypeParameter.description("Expected response type, in this case \"token\", i.e. an access token"),
          clientIdParameter,
          scopesParameter,
          redirectParameter,
          promptParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Redirect url specified in the request parameters."));

        getMockMvc().perform(get)
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
            .session(session);

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("Expected response type, in this case \"id_token\""),
            clientIdParameter,
            scopesParameter,
            redirectParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes id_token in the reply fragment if successful"));

        MvcResult mvcResult = getMockMvc().perform(get)
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
            .session(session);

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("Expected response type, in this case \"token id_token\", indicating both an access token and an ID token."),
            clientIdParameter,
            scopesParameter,
            redirectParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes access_token and id_token in the reply fragment if successful"));

        MvcResult mvcResult = getMockMvc().perform(get)
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
            .session(session);

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("Expected response type, in this case \"id_token code\", indicating a request for an ID token and an authorization code."),
            clientIdParameter,
            scopesParameter,
            redirectParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes code and id_token in the reply fragment if successful"));

        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isFound())
            .andDo(print())
            .andDo(document("{ClassName}/{methodName}",
                responseHeaders,
                requestParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Assert.assertThat(location, containsString("id_token="));
        Assert.assertThat(location, containsString("code="));
    }

    @Ignore("there is no use for retrieving both an access token and a code in the UAA")
    @Test
    public void getIdTokenAndAccessTokenAndCode() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            new MockMvcUtils.MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = get("/oauth/authorize")
            .accept(APPLICATION_FORM_URLENCODED)
            .param(RESPONSE_TYPE, "token id_token code")
            .param(CLIENT_ID, "app")
            .param(SCOPE, "openid")
            .param(REDIRECT_URI, "http://localhost:8080/app/")
            .session(session);

        Snippet requestParameters = requestParameters(
            responseTypeParameter.description("Expected response type, in this case \"token id_token code\", indicating a request for an (implicitly granted) access token, an ID token, and an authorization code."),
            clientIdParameter,
            scopesParameter,
            redirectParameter
        );

        Snippet responseHeaders = responseHeaders(headerWithName("Location").description("Location as defined in the spec includes access_token, id_token, and code in the reply fragment if successful"));

        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isFound())
            .andDo(print())
            .andDo(document("{ClassName}/{methodName}",
                responseHeaders,
                requestParameters)).andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Assert.assertThat(location, containsString("id_token="));
        Assert.assertThat(location, containsString("access_token="));
        Assert.assertThat(location, containsString("code="));
    }
}
