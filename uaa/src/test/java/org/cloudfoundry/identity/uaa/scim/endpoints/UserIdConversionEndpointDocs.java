package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Collections;
import java.util.List;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class UserIdConversionEndpointDocs extends EndpointDocs {
    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private final String clientId = generator.generate().toLowerCase();
    private final String clientSecret = generator.generate().toLowerCase();
    private ScimUser bob;
    private ScimUser dwayne;
    private String userLookupToken;

    @BeforeEach
    void setUp() throws Exception {
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc,
                "admin",
                "adminsecret",
                "clients.read clients.write clients.secret scim.read scim.write clients.admin",
                null
        );
        bob = new ScimUser(null, "bob" + generator.generate() + "@test.org", "Bob", "Exemplar");
        bob.setPrimaryEmail(bob.getUserName());
        bob.setPassword("password");
        bob = MockMvcUtils.createUser(mockMvc, adminToken, bob);
        dwayne = new ScimUser(null, "dwayne" + generator.generate() + "@test.org", "Dwayne", "Exemplar");
        dwayne.setPrimaryEmail(dwayne.getUserName());
        dwayne.setPassword("password");
        dwayne = MockMvcUtils.createUser(mockMvc, adminToken, dwayne);
        List<String> scopes = Collections.singletonList("scim.userids");
        MockMvcUtils.createClient(mockMvc,
                adminToken,
                clientId,
                clientSecret,
                null,
                scopes,
                Collections.singletonList("client_credentials"),
                "scim.userids"
        );
        userLookupToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                mockMvc,
                clientId,
                clientSecret,
                "scim.userids",
                null,
                true
        );
    }

    @Test
    void lookUpIds() throws Exception {
        MockHttpServletRequestBuilder get = get("/ids/Users")
                .header("Authorization", "Bearer " + userLookupToken)
                .param("filter", "userName eq \"%s\" or id eq \"%s\"".formatted(bob.getUserName(), dwayne.getId()))
                .param("sortOrder", "descending")
                .param("startIndex", "1")
                .param("count", "10")
                .param("includeInactive", "true");

        Snippet requestHeader = requestHeaders(
                headerWithName("Authorization").description("Bearer token with authorization for `scim.userids` scope")
        );

        Snippet requestParams = queryParameters(
                parameterWithName("filter").required().description("SCIM filter for users over `userName`, `id`, and `origin`, using only the `eq` comparison operator").attributes(key("type").value(STRING)),
                parameterWithName("sortOrder").optional("ascending").description("sort by username in `ascending` or `descending` order").attributes(key("type").value(STRING)),
                parameterWithName("startIndex").optional("1").description("display paged results beginning at specified index").attributes(key("type").value(NUMBER)),
                parameterWithName("count").optional("100").description("number of results to return per page").attributes(key("type").value(NUMBER)),
                parameterWithName("includeInactive").optional("false").description("include users from inactive identity providers").attributes(key("type").value(BOOLEAN))
        );

        Snippet responseFields = responseFields(
                fieldWithPath("totalResults").description("The number of results which matched the filter"),
                fieldWithPath("startIndex").description("The index of the first item of this page of results"),
                fieldWithPath("itemsPerPage").description("The page size used in producing this page of results"),
                fieldWithPath("schemas").description("`[\"urn:scim:schemas:core:1.0\"]`"),
                fieldWithPath("resources[].id").description("The globally unique identifier for this user"),
                fieldWithPath("resources[].userName").description("The username"),
                fieldWithPath("resources[].origin").description("The origin of the user, e.g. an identity provider alias")
        );

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeader,
                        requestParams,
                        responseFields
                ));
    }
}
