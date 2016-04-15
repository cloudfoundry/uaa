/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.scim;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Date;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ScimUserEndpointDocs extends InjectedMockContextTest {


    private String scimReadToken;
    private String scimWriteToken;
    ScimUser user;

    @Before
    public void setUp() throws Exception {
        scimReadToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            "admin",
            "adminsecret",
            "scim.read",
            null,
            true
        );
        scimWriteToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            "admin",
            "adminsecret",
            "scim.write",
            null,
            true
        );

        String username = new RandomValueStringGenerator().generate()+"@test.org";
        user = new ScimUser(null, username, "given name", "family name");
        user.setPrimaryEmail(username);
        user.setPassword("secret");

        user = MockMvcUtils.utils().createUser(getMockMvc(), scimWriteToken, user);
        ApprovalStore approvalStore = getWebApplicationContext().getBean(ApprovalStore.class);
        approvalStore.addApproval(
            new Approval()
                .setClientId("client id")
                .setUserId(user.getId())
            .setExpiresAt(new Date(System.currentTimeMillis()+10000))
            .setScope("scim.read")
            .setStatus(Approval.ApprovalStatus.APPROVED)
        );
    }

    @Test
    public void printApproval() {
        System.out.println(JsonUtils.writeValueAsString(new Approval()
                                                            .setUserId("userIdValue")
                                                            .setClientId("clientId")
                                                            .setScope("scope1")
                                                            .setExpiresAt(Approval.timeFromNow(100))
                                                            .setStatus(Approval.ApprovalStatus.DENIED)));
    }

    @Test
    public void test_GET_Users() throws Exception {
        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath("startIndex").type(NUMBER).description("The starting index of the search results when paginated. Index starts with 1."),
            fieldWithPath("itemsPerPage").type(NUMBER).description("The maximum number of items returned per request"),
            fieldWithPath("totalResults").type(NUMBER).description("Verifier key"),
            fieldWithPath("schemas").type(ARRAY).description("SCIM Schemas used, currently always set to [ \"urn:scim:schemas:core:1.0\" ]"),
            fieldWithPath("resources").type(ARRAY).description("A list of SCIM user objects retrieved by the search."),
            fieldWithPath("resources[].id").type(STRING).description("Unique user identifier."),
            fieldWithPath("resources[].userName").type(STRING).description("User name of the user, typically an email address."),
            fieldWithPath("resources[].name").type(OBJECT).description("A map with the user's first name and last name."),
            fieldWithPath("resources[].name.familyName").type(STRING).description("The user's last name."),
            fieldWithPath("resources[].name.givenName").type(STRING).description("The user's first name."),
            fieldWithPath("resources[].emails").type(ARRAY).description("The user's email addresses."),
            fieldWithPath("resources[].emails[].value").type(ARRAY).description("The email address."),
            fieldWithPath("resources[].emails[].primary").type(BOOLEAN).description("Set to true if this is the user's primary email address."),
            fieldWithPath("resources[].groups").type(ARRAY).description("A list of groups the user belongs to."),
            fieldWithPath("resources[].groups[].value").type(STRING).description("Unique group identifier"),
            fieldWithPath("resources[].groups[].display").type(STRING).description("The group display name, also referred to as scope during authorization."),
            fieldWithPath("resources[].groups[].type").type(STRING).description("Membership type - DIRECT means the user is directly associated with the group. INDIRECT means that the membership has been inherited from nested groups."),
            fieldWithPath("resources[].approvals").type(ARRAY).description("A list of approvals for this user. Approvals are user's explicit approval or rejection for an application."),
            fieldWithPath("resources[].approvals[].userId").type(STRING).description("The user id on the approval. Will be the same as the id field."),
            fieldWithPath("resources[].approvals[].clientId").type(STRING).description("The client id on the approval. Represents the application this approval or denial was for."),
            fieldWithPath("resources[].approvals[].scope").type(STRING).description("The scope on the approval. Will be a group display value."),
            fieldWithPath("resources[].approvals[].status").type(STRING).description("The status of the approval. APPROVED or DENIED are the only valid values."),
            fieldWithPath("resources[].approvals[].lastUpdatedAt").type(STRING).description("Date this approval was last updated."),
            fieldWithPath("resources[].approvals[].expiresAt").type(STRING).description("Date this approval will expire."),
            fieldWithPath("resources[].active").type(BOOLEAN).description("If this user is active. False is a soft delete. The user will not be able to log in."),
            fieldWithPath("resources[].verified").type(BOOLEAN).description("True, if this user has verified her/his email address."),
            fieldWithPath("resources[].origin").type(STRING).description("The alias of the identity provider that authenticated this user. 'uaa' is an internal UAA user."),
            fieldWithPath("resources[].zoneId").type(STRING).description("The zone this user belongs to. 'uaa' is the default zone."),
            fieldWithPath("resources[].passwordLastModified").type(STRING).description("The timestamp this user's password was last changed."),
        };

        ParameterDescriptor[] parameters = {
            RequestDocumentation.parameterWithName("filter").description("SCIM filter for searching").attributes(key("constraints").value("Optional"), key("type").value(STRING), key("default").value(null)),
            RequestDocumentation.parameterWithName("sortBy").description("sort by what field").attributes(key("constraints").value("Optional"), key("type").value(STRING), key("default").value("created")),
            RequestDocumentation.parameterWithName("sortOrder").description("sort order, ascending/descending").attributes(key("constraints").value("Optional"), key("type").value(STRING), key("default").value("ascending")),
            RequestDocumentation.parameterWithName("startIndex").description("Pagination start index, index starts with 1").attributes(key("constraints").value("Optional"), key("type").value(NUMBER), key("default").value(1)),
            RequestDocumentation.parameterWithName("count").description("Max number of results to be returned").attributes(key("constraints").value("Optional"), key("type").value(NUMBER), key("default").value(100)),
        };

        Snippet responseFields = responseFields(fieldDescriptors);
        Snippet requetParameters = requestParameters(parameters);

        getMockMvc().perform(
            get("/Users")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer "+scimReadToken)
                .param("filter", String.format("id eq \"%s\" or email eq \"%s\"", user.getId(), user.getUserName()))
                .param("sortBy", "email")
                .param("count", "50")
                .param("sortOrder", "ascending")
                .param("startIndex", "1")
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                         preprocessRequest(prettyPrint()),
                         preprocessResponse(prettyPrint()),
                         requestHeaders(
                             headerWithName("Authorization").description("Access token with scim.read or uaa.admin required")
                         ),
                         requetParameters,
                         responseFields
                )
            );
    }


}
