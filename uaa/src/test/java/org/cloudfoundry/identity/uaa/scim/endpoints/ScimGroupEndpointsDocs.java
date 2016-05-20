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
package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Type.USER;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public class ScimGroupEndpointsDocs extends InjectedMockContextTest {

    private final RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private final FieldDescriptor displayNameRequestField = fieldWithPath("displayName").required().description("An identifier, unique within the identity zone");
    private final FieldDescriptor descriptionRequestField = fieldWithPath("description").optional(null).type(STRING).description("Human readable description of the group, displayed e.g. when approving scopes");
    private final FieldDescriptor membersRequestField = fieldWithPath("members").optional(null).type(ARRAY).description("Members to be included in the group");
    private final FieldDescriptor memberValueRequestField = fieldWithPath("members[].value").constrained("Required for each item in `members`").type(STRING).description("The globally-unique ID of the member entity, either a user ID or another group ID");
    private final FieldDescriptor memberTypeRequestField = fieldWithPath("members[].type").optional(USER).type(STRING).description("Either `\"USER\"` or `\"GROUP\"`");
    private final FieldDescriptor memberOriginRequestField = fieldWithPath("members[].origin").optional("uaa").type(STRING).description("The alias of the identity provider that authenticated this user. `\"uaa\"` is an internal UAA user.");
    private String scimReadToken;
    private String scimWriteToken;

    private static FieldDescriptor[] documentScimGroupResponseFields(String path) {
        String prefix = hasText(path) ? path + "." : "";

        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath(prefix + "id").description("The globally unique group ID"),
            fieldWithPath(prefix + "displayName").description("The identifier specified upon creation of the group, unique within the identity zone"),
            fieldWithPath(prefix + "description").description("Human readable description of the group, displayed e.g. when approving scopes"),
            fieldWithPath(prefix + "members").description("Array of group members"),
            fieldWithPath(prefix + "members[].value").description("Globally unique identifier of the member, either a user ID or another group ID"),
            fieldWithPath(prefix + "members[].type").description("Either `\"USER\"` or `\"GROUP\"`"),
            fieldWithPath(prefix + "members[].origin").description("The alias of the identity provider that authenticated this user. `\"uaa\"` is an internal UAA user."),
            fieldWithPath(prefix + "zoneId").description("Identifier for the identity zone to which the group belongs"),
            fieldWithPath(prefix + "meta.version").description("The version of the group entity"),
            fieldWithPath(prefix + "meta.created").description("The time the group was created"),
            fieldWithPath(prefix + "meta.lastModified").description("The time the group was last updated"),
            fieldWithPath(prefix + "schemas").description("`[ \"urn:scim:schemas:core:1.0\" ]`")
        };

        return fieldDescriptors;
    }

    private final Snippet scimGroupRequestFields = requestFields(
        displayNameRequestField,
        descriptionRequestField,
        membersRequestField,
        memberValueRequestField,
        memberTypeRequestField,
        memberOriginRequestField
    );

    @Before
    public void setUp() throws Exception {
        scimReadToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret",
            "scim.read", null, true);

        scimWriteToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret",
            "scim.write", null, true);
    }

    @Test
    public void createRetrieveUpdateListScimGroup() throws Exception {
        // Create

        ScimGroup scimGroup = new ScimGroup();
        scimGroup.setDisplayName("Cool Group Name");
        scimGroup.setDescription("the cool group");

        addMemberToGroup(scimGroup);

        Snippet responseFields = responseFields(documentScimGroupResponseFields(""));

        ResultActions createResult = createScimGroupHelper(scimGroup)
            .andDo(document("{ClassName}/createScimGroup",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.write`")
                ),
                scimGroupRequestFields,
                responseFields));

        scimGroup = JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        scimGroup.setDisplayName("Cooler Group Name for Update");


        // Update

        MockHttpServletRequestBuilder put = put("/Groups/{groupId}", scimGroup.getId())
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("If-Match", scimGroup.getVersion())
            .contentType(APPLICATION_JSON)
            .content(serializeWithoutMeta(scimGroup));

        ResultActions updateResult = getMockMvc().perform(put).andExpect(status().isOk())
            .andDo(document("{ClassName}/updateScimGroup",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("groupId").description("Globally unique identifier of the group to update")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.write`"),
                    headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildcard (*) accepted.")
                ),
                scimGroupRequestFields,
                responseFields));


        // Retrieve

        scimGroup = JsonUtils.readValue(updateResult.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        MockHttpServletRequestBuilder get = get("/Groups/{groupId}", scimGroup.getId())
            .header("Authorization", "Bearer " + scimReadToken);

        ResultActions retrieveResult = getMockMvc().perform(get).andExpect(status().isOk())
            .andDo(document("{ClassName}/retrieveScimGroup",
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("groupId").description("Globally unique identifier of the group to retrieve")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.read`")
                ),
                responseFields));


        // List

        scimGroup = JsonUtils.readValue(retrieveResult.andReturn().getResponse().getContentAsString(), ScimGroup.class);

        Snippet requestParameters = requestParameters(
            parameterWithName("filter").optional("id pr").type(STRING).description("A SCIM filter over groups"),
            parameterWithName("sortBy").optional("created").type(STRING).description("The field of the SCIM group to sort by"),
            parameterWithName("sortOrder").optional("ascending").type(NUMBER).description("Sort in `ascending` or `descending` order"),
            parameterWithName("startIndex").optional("1").type(NUMBER).description("The index of the first result of this page within all matches"),
            parameterWithName("count").optional("100").type(NUMBER).description("Maximum number of results to return in a single page")
        );

        MockHttpServletRequestBuilder getList = get("/Groups")
            .header("Authorization", "Bearer " + scimReadToken)
            .param("filter", String.format("id eq \"%s\" or displayName eq \"%s\"", scimGroup.getId(), scimGroup.getDisplayName()))
            .param("sortBy", "lastModified")
            .param("count", "50")
            .param("sortOrder", "descending")
            .param("startIndex", "1");

        List<FieldDescriptor> fields = new ArrayList<>(asList(documentScimGroupResponseFields("resources[]")));
        fields.addAll(asList(
            fieldWithPath("itemsPerPage").description("The page-size used to produce the current page of results"),
            fieldWithPath("startIndex").description("The index of the first result of this page within all matches"),
            fieldWithPath("totalResults").description("The number of groups that matched the given filter"),
            fieldWithPath("schemas").description("`[ \"urn:scim:schemas:core:1.0\" ]`")
        ));
        Snippet listUserResponseFields = responseFields(fields.toArray(new FieldDescriptor[fields.size()]));

        getMockMvc().perform(getList).andExpect(status().isOk())
            .andDo(document("{ClassName}/listScimGroups",
                preprocessResponse(prettyPrint()),
                requestParameters,
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.read`")
                ),
                listUserResponseFields));


        // Delete

        MockHttpServletRequestBuilder delete = delete("/Groups/{groupId}", scimGroup.getId())
            .header("Authorization", "Bearer " + scimWriteToken);

        getMockMvc().perform(delete).andExpect(status().isOk())
            .andDo(document("{ClassName}/deleteScimGroup",
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("groupId").description("The globally unique identifier of the group to delete")
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token with scope `scim.read`"),
                    headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildcard (*) accepted.").attributes(key("constraints").value("Optional (defaults to `*`)")).optional()
                ),
                responseFields));
    }

    private static String serializeWithoutMeta(ScimGroup scimGroup) {
        Map<String, Object> content = JsonUtils.readValue(JsonUtils.writeValueAsString(scimGroup), new TypeReference<Map<String, Object>>() {
        });
        content.remove("id");
        content.remove("zoneId");
        content.remove("meta");
        content.remove("schemas");
        return JsonUtils.writeValueAsString(content);
    }

    private ResultActions createScimGroupHelper(ScimGroup scimGroup) throws Exception {
        MockHttpServletRequestBuilder post = post("/Groups")
            .header("Authorization", "Bearer " + scimWriteToken)
            .contentType(APPLICATION_JSON)
            .content(serializeWithoutMeta(scimGroup));

        return getMockMvc().perform(post).andExpect(status().isCreated());
    }

    private void addMemberToGroup(ScimGroup scimGroup) throws Exception {
        String userName = generator.generate();
        ScimUser member = new ScimUser(null, userName, "cool-name", "cool-familyName");
        member.setPrimaryEmail("cool@chill.com");
        member = MockMvcUtils.utils().createUser(getMockMvc(), scimWriteToken, member);
        scimGroup.setMembers(Collections.singletonList(new ScimGroupMember(member.getId())));
    }

}
