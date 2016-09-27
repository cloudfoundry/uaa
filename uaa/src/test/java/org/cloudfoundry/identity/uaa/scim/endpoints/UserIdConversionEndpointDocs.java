/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.List;

import static java.lang.String.format;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
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
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UserIdConversionEndpointDocs extends InjectedMockContextTest{

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId = generator.generate().toLowerCase();
    private String clientSecret = generator.generate().toLowerCase();
    private ScimUser bob;
    private ScimUser dwayne;
    private String userLookupToken;

    @Before
    public void setUp() throws Exception {
        getWebApplicationContext().getBean(UserIdConversionEndpoints.class).setEnabled(true);

        String adminToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin", null);
        bob = new ScimUser(null, "bob"+generator.generate()+"@test.org", "Bob", "Exemplar");
        bob.setPrimaryEmail(bob.getUserName());
        bob.setPassword("password");
        bob = utils().createUser(getMockMvc(),adminToken, bob);
        dwayne = new ScimUser(null, "dwayne"+generator.generate()+"@test.org", "Dwayne", "Exemplar");
        dwayne.setPrimaryEmail(dwayne.getUserName());
        dwayne.setPassword("password");
        dwayne = utils().createUser(getMockMvc(),adminToken, dwayne);
        List<String> scopes = Arrays.asList("scim.userids");
        utils().createClient(getMockMvc(), adminToken, clientId, clientSecret, null, scopes, Arrays.asList(new String[]{"client_credentials"}), "scim.userids");
        userLookupToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), clientId, clientSecret, "scim.userids", null, true);
    }

    @Test
    public void lookUpIds() throws Exception {
        MockHttpServletRequestBuilder get = get("/ids/Users")
            .header("Authorization", "Bearer " + userLookupToken)
            .param("filter", format("userName eq \"%s\" or id eq \"%s\"", bob.getUserName(), dwayne.getId()))
            .param("sortOrder", "descending")
            .param("startIndex", "1")
            .param("count", "10")
            .param("includeInactive", "true");

        Snippet requestHeader = requestHeaders(
            headerWithName("Authorization").description("Bearer token with authorization for `scim.userids` scope")
        );

        Snippet requestParams = requestParameters(
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

        getMockMvc().perform(get)
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
