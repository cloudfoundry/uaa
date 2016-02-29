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
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.SCOPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.STATE;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuthorizeEndpointDocs extends InjectedMockContextTest {
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
                .param(REDIRECT_URI, "http://redirect.to/app")
                .session(session);

        Snippet requestParameters = requestParameters(
                parameterWithName(RESPONSE_TYPE).description("either \"code\" for requesting an authorization code or \"token\" for an access token, as per OAuth spec"),
                parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client"),
                parameterWithName(SCOPE).description("requested scopes"),
                parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied), optional if pre-registered by the client")
        );

        getMockMvc().perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessRequest(prettyPrint()),
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
                parameterWithName(RESPONSE_TYPE).description("either \"code\" for requesting an authorization code or \"token\" for an access token, as per OAuth spec"),
                parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client"),
                parameterWithName(SCOPE).description("requested scopes"),
                parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied), optional if pre-registered by the client")
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
                        preprocessRequest(prettyPrint()),
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
                .param(REDIRECT_URI, "https://uaa.cloudfoundry.com/redirect/cf")
                .param(STATE, new RandomValueStringGenerator().generate());

        Snippet requestParameters = requestParameters(
                parameterWithName(RESPONSE_TYPE).description("either \"code\" for requesting an authorization code or \"token\" for an access token, as per OAuth spec"),
                parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client"),
                parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied), optional if pre-registered by the client"),
                parameterWithName(STATE).description("any random string to be returned in the Location header as a query parameter, used to achieve per-request customization")
        );

        getMockMvc().perform(get)
                .andExpect(status().isFound())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessRequest(prettyPrint()),
                        requestParameters));
    }
}
