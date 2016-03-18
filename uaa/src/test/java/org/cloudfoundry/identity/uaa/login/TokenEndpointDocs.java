package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.ssl.Base64;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.STATE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenEndpointDocs extends InjectedMockContextTest {

    private ScimUser user;

    @Test
    public void getTokenUsingAuthCodeGrant() throws Exception {
        createUser();
        String cfAccessToken = utils().getUserOAuthAccessToken(
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
            .param(REDIRECT_URI, redirect);

        Snippet requestParameters = requestParameters(
            parameterWithName(RESPONSE_TYPE).description("the type of token that should be issued."),
            parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client"),
            parameterWithName(REDIRECT_URI).description("redirection URI to which the authorization server will send the user-agent back once access is granted (or denied)"),
            parameterWithName("code").description("the authorization code, obtained from /oauth/authorize, issued for the user"),
            parameterWithName(GRANT_TYPE).description("the type of authentication being used to obtain the token, in this case `authorization_code`"),
            parameterWithName("client_secret").description("the secret passphrase configured for the OAuth client")
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
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            parameterWithName(RESPONSE_TYPE).description("the type of token that should be issued."),
            parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client"),
            parameterWithName(GRANT_TYPE).description("the type of authentication being used to obtain the token, in this case `client_credentials`"),
            parameterWithName("client_secret").description("the secret passphrase configured for the OAuth client")
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
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            parameterWithName(RESPONSE_TYPE).description("the type of token that should be issued."),
            parameterWithName(CLIENT_ID).description("a unique string representing the registration information provided by the client"),
            parameterWithName(GRANT_TYPE).description("the type of authentication being used to obtain the token, in this case `password`"),
            parameterWithName("client_secret").description("the secret passphrase configured for the OAuth client"),
            parameterWithName("username").description("the username for the user trying to get a token"),
            parameterWithName("password").description("the password for the user trying to get a token")
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
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            parameterWithName(RESPONSE_TYPE).description("the type of token that should be issued."),
            parameterWithName(GRANT_TYPE).description("the type of authentication being used to obtain the token, in this case `password`"),
            parameterWithName("username").description("the username for the user trying to get a token"),
            parameterWithName("password").description("the password for the user trying to get a token")
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
            new MockMvcUtils.MockSecurityContext(principal)
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
            .param(RESPONSE_TYPE, "token");

        Snippet requestParameters = requestParameters(
            parameterWithName(RESPONSE_TYPE).description("the type of token that should be issued."),
            parameterWithName(GRANT_TYPE).description("the type of authentication being used to obtain the token, in this case `password`"),
            parameterWithName("passcode").description("the one-time passcode for the user which can be retrieved by going to `/passcode`")
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

    private void createUser() throws Exception {
        TestClient testClient = new TestClient(getMockMvc());
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", null);
        user = new ScimUser(null, new RandomValueStringGenerator().generate()+"@test.org", "name", "familyName");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = MockMvcUtils.utils().createUser(getMockMvc(), adminToken, user);
        user.setPassword("secr3T");
    }


}
