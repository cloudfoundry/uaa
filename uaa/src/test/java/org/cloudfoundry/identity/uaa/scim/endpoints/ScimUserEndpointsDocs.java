package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ScimUserEndpointsDocs extends InjectedMockContextTest {

    ScimUserProvisioning userProvisioning;
    TestClient testClient;

    @Before
    public void setUp() {
        userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        testClient = new TestClient(getMockMvc());
    }

    @Test
    public void getUserVerificationLink() throws Exception {
        String accessToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");

        String email = "joel@example.com";
        ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
        joel.setVerified(false);
        joel.addEmail(email);
        joel = userProvisioning.createUser(joel, "pas5Word");

        MockHttpServletRequestBuilder get = get("/Users/{userId}/verify-link", joel.getId())
            .header("Authorization", "Bearer " + accessToken)
            .param("redirect_uri", "http://redirect.to/app")
            .accept(APPLICATION_JSON);

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("The bearer token, with a pre-amble of `Bearer`"));
        Snippet requestParameters = requestParameters(parameterWithName("redirect_uri").required().description("Location where the user will be redirected after verifying by clicking the verification link").attributes(key("type").value(STRING)));
        Snippet responseFields = responseFields(fieldWithPath("verify_link").description("Location the user must visit and authenticate to verify"));

        Snippet pathParameters = pathParameters(
            RequestDocumentation.parameterWithName("userId").description("The ID of the user to verify")
        );
        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                pathParameters, requestHeaders, requestParameters, responseFields))
            ;
    }

    @Test
    public void directlyVerifyUser() throws Exception {
        String accessToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");

        String email = "billy_o@example.com";
        ScimUser billy = new ScimUser(null, email, "William", "d'Orange");
        billy.setVerified(false);
        billy.addEmail(email);
        billy.setVersion(12);
        billy = userProvisioning.createUser(billy, "pas5Word");

        Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("The bearer token, with a pre-amble of `Bearer`"),
            headerWithName("If-Match").description("(Optional) The expected current version of the user, which will prevent update if the version does not match"));

        Snippet pathParameters = pathParameters(
            RequestDocumentation.parameterWithName("userId").description("The ID of the user to verify")
        );

        MockHttpServletRequestBuilder get = get("/Users/{userId}/verify", billy.getId())
            .header("Authorization", "Bearer " + accessToken)
            .header("If-Match", "12")
            .accept(APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                pathParameters, requestHeaders))
        ;
    }
}
