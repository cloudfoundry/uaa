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

import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Collections;
import java.util.Date;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
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
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ScimUserEndpointDocs extends InjectedMockContextTest {

    private final String startIndexDescription = "The starting index of the search results when paginated. Index starts with 1.";
    private final String countAndItemsPerPageDescription = "The maximum number of items returned per request.";
    private final String totalResultsDescription = "Number of results in result set.";

    private final String userIdDescription = "Unique user identifier.";
    private final String resourceDescription = "A list of SCIM user objects retrieved by the search.";
    private final String usernameDescription = "User name of the user, typically an email address.";
    private final String nameObjectDescription = "A map with the user's first name and last name.";
    private final String lastnameDescription = "The user's last name.";
    private final String firstnameDescription = "The user's first name.";
    private final String emailListDescription = "The user's email addresses.";
    private final String emailDescription = "The email address.";
    private final String emailPrimaryDescription = "Set to true if this is the user's primary email address.";
    private final String groupDescription = "A list of groups the user belongs to.";

    private final String schemasDescription = "SCIM Schemas used, currently always set to [ \"urn:scim:schemas:core:1.0\" ]";
    private final String groupIdDescription = "Unique group identifier";
    private final String groupDisplayNameDescription = "The group display name, also referred to as scope during authorization.";
    private final String membershipTypeDescription = "Membership type - DIRECT means the user is directly associated with the group. INDIRECT means that the membership has been inherited from nested groups.";
    private final String approvalsListDescription = "A list of approvals for this user. Approvals are user's explicit approval or rejection for an application.";
    private final String approvalUserIdDescription = "The user id on the approval. Will be the same as the id field.";
    private final String approvalClientIdDescription = "The client id on the approval. Represents the application this approval or denial was for.";
    private final String approvalScopeDescription = "The scope on the approval. Will be a group display value.";
    private final String approvalStatusDescription = "The status of the approval. APPROVED or DENIED are the only valid values.";
    private final String approvalsLastUpdatedAtDescription = "Date this approval was last updated.";
    private final String approvalsExpiresAtDescription = "Date this approval will expire.";
    private final String userActiveDescription = "If this user is active. False is a soft delete. The user will not be able to log in.";
    private final String userVerifiedDescription = "True, if this user has verified her/his email address.";
    private final String userOriginDescription = "The alias of the identity provider that authenticated this user. 'uaa' is an internal UAA user.";
    private final String userZoneIdDescription = "The zone this user belongs to. 'uaa' is the default zone.";
    private final String passwordLastModifiedDescription = "The timestamp this user's password was last changed.";
    private final String externalIdDescription = "External user ID if authenticated through external identity provider.";
    private final String passwordDescription = "User's password.";

    FieldDescriptor[] searchResponseFields = {
        fieldWithPath("startIndex").type(NUMBER).description(startIndexDescription),
        fieldWithPath("itemsPerPage").type(NUMBER).description(countAndItemsPerPageDescription),
        fieldWithPath("totalResults").type(NUMBER).description(totalResultsDescription),
        fieldWithPath("schemas").type(ARRAY).description(schemasDescription),
        fieldWithPath("resources").type(ARRAY).description(resourceDescription),
        fieldWithPath("resources[].id").type(STRING).description(userIdDescription),
        fieldWithPath("resources[].userName").type(STRING).description(usernameDescription),
        fieldWithPath("resources[].name").type(OBJECT).description(nameObjectDescription),
        fieldWithPath("resources[].name.familyName").type(STRING).description(lastnameDescription),
        fieldWithPath("resources[].name.givenName").type(STRING).description(firstnameDescription),
        fieldWithPath("resources[].emails").type(ARRAY).description(emailListDescription),
        fieldWithPath("resources[].emails[].value").type(ARRAY).description(emailDescription),
        fieldWithPath("resources[].emails[].primary").type(BOOLEAN).description(emailPrimaryDescription),
        fieldWithPath("resources[].groups").type(ARRAY).description(groupDescription),
        fieldWithPath("resources[].groups[].value").type(STRING).description(groupIdDescription),
        fieldWithPath("resources[].groups[].display").type(STRING).description(groupDisplayNameDescription),
        fieldWithPath("resources[].groups[].type").type(STRING).description(membershipTypeDescription),
        fieldWithPath("resources[].approvals").type(ARRAY).description(approvalsListDescription),
        fieldWithPath("resources[].approvals[].userId").type(STRING).description(approvalUserIdDescription),
        fieldWithPath("resources[].approvals[].clientId").type(STRING).description(approvalClientIdDescription),
        fieldWithPath("resources[].approvals[].scope").type(STRING).description(approvalScopeDescription),
        fieldWithPath("resources[].approvals[].status").type(STRING).description(approvalStatusDescription),
        fieldWithPath("resources[].approvals[].lastUpdatedAt").type(STRING).description(approvalsLastUpdatedAtDescription),
        fieldWithPath("resources[].approvals[].expiresAt").type(STRING).description(approvalsExpiresAtDescription),
        fieldWithPath("resources[].active").type(BOOLEAN).description(userActiveDescription),
        fieldWithPath("resources[].verified").type(BOOLEAN).description(userVerifiedDescription),
        fieldWithPath("resources[].origin").type(STRING).description(userOriginDescription),
        fieldWithPath("resources[].zoneId").type(STRING).description(userZoneIdDescription),
        fieldWithPath("resources[].passwordLastModified").type(STRING).description(passwordLastModifiedDescription),
    };

    Snippet createFields = requestFields(
        fieldWithPath("userName").required().type(STRING).description(usernameDescription),
        fieldWithPath("password").required().type(STRING).description(passwordDescription),
        fieldWithPath("name").required().type(OBJECT).description(nameObjectDescription),
        fieldWithPath("name.familyName").required().type(STRING).description(lastnameDescription),
        fieldWithPath("name.givenName").required().type(STRING).description(firstnameDescription),
        fieldWithPath("emails").required().type(ARRAY).description(emailListDescription),
        fieldWithPath("emails[].value").required().type(ARRAY).description(emailDescription),
        fieldWithPath("emails[].primary").required().type(BOOLEAN).description(emailPrimaryDescription),
        fieldWithPath("active").optional(true).type(BOOLEAN).description(userActiveDescription),
        fieldWithPath("verified").optional(false).type(BOOLEAN).description(userVerifiedDescription),
        fieldWithPath("origin").optional(OriginKeys.UAA).type(STRING).description(userOriginDescription),
        fieldWithPath("externalId").optional(null).type(STRING).description(externalIdDescription),
        fieldWithPath("schemas").optional().ignored().type(ARRAY).description(schemasDescription),
        fieldWithPath("meta").optional().ignored().type(STRING).description("SCIM object meta data not read.")
    );

    FieldDescriptor[] createResponse = {
        fieldWithPath("schemas").type(ARRAY).description(schemasDescription),
        fieldWithPath("id").type(STRING).description(userIdDescription),
        fieldWithPath("userName").type(STRING).description(usernameDescription),
        fieldWithPath("name").type(OBJECT).description(nameObjectDescription),
        fieldWithPath("name.familyName").type(STRING).description(lastnameDescription),
        fieldWithPath("name.givenName").type(STRING).description(firstnameDescription),
        fieldWithPath("emails").type(ARRAY).description(emailListDescription),
        fieldWithPath("emails[].value").type(ARRAY).description(emailDescription),
        fieldWithPath("emails[].primary").type(BOOLEAN).description(emailPrimaryDescription),
        fieldWithPath("groups").type(ARRAY).description(groupDescription),
        fieldWithPath("groups[].value").type(STRING).description(groupIdDescription),
        fieldWithPath("groups[].display").type(STRING).description(groupDisplayNameDescription),
        fieldWithPath("groups[].type").type(STRING).description(membershipTypeDescription),
        fieldWithPath("approvals").type(ARRAY).description(approvalsListDescription),
        fieldWithPath("active").type(BOOLEAN).description(userActiveDescription),
        fieldWithPath("verified").type(BOOLEAN).description(userVerifiedDescription),
        fieldWithPath("origin").type(STRING).description(userOriginDescription),
        fieldWithPath("zoneId").type(STRING).description(userZoneIdDescription),
        fieldWithPath("passwordLastModified").type(STRING).description(passwordLastModifiedDescription),
        fieldWithPath("externalId").type(STRING).description(externalIdDescription),
        fieldWithPath("meta").type(STRING).description("SCIM object meta data."),
        fieldWithPath("meta.version").type(NUMBER).description("Object version."),
        fieldWithPath("meta.lastModified").type(STRING).description("Object last modified date."),
        fieldWithPath("meta.created").type(STRING).description("Object created date."),
    };

    Snippet updateFields = requestFields(
        fieldWithPath("schemas").ignored().type(ARRAY).description(schemasDescription),
        fieldWithPath("id").ignored().type(STRING).description(userIdDescription),
        fieldWithPath("userName").required().type(STRING).description(usernameDescription),
        fieldWithPath("name").required().type(OBJECT).description(nameObjectDescription),
        fieldWithPath("name.familyName").required().type(STRING).description(lastnameDescription),
        fieldWithPath("name.givenName").required().type(STRING).description(firstnameDescription),
        fieldWithPath("emails").required().type(ARRAY).description(emailListDescription),
        fieldWithPath("emails[].value").required().type(ARRAY).description(emailDescription),
        fieldWithPath("emails[].primary").required().type(BOOLEAN).description(emailPrimaryDescription),
        fieldWithPath("groups").ignored().type(ARRAY).description("Groups are not created at this time."),
        fieldWithPath("approvals").ignored().type(ARRAY).description("Approvals are not created at this time"),
        fieldWithPath("active").optional(true).type(BOOLEAN).description(userActiveDescription),
        fieldWithPath("verified").optional(false).type(BOOLEAN).description(userVerifiedDescription),
        fieldWithPath("origin").optional(OriginKeys.UAA).type(STRING).description(userOriginDescription),
        fieldWithPath("zoneId").ignored().type(STRING).description(userZoneIdDescription),
        fieldWithPath("passwordLastModified").ignored().type(STRING).description(passwordLastModifiedDescription),
        fieldWithPath("externalId").optional(null).type(STRING).description(externalIdDescription),
        fieldWithPath("meta").ignored().type(STRING).description("SCIM object meta data not read.")
    );

    FieldDescriptor[] updateResponse = {
        fieldWithPath("schemas").type(ARRAY).description(schemasDescription),
        fieldWithPath("id").type(STRING).description(userIdDescription),
        fieldWithPath("userName").type(STRING).description(usernameDescription),
        fieldWithPath("name").type(OBJECT).description(nameObjectDescription),
        fieldWithPath("name.familyName").type(STRING).description(lastnameDescription),
        fieldWithPath("name.givenName").type(STRING).description(firstnameDescription),
        fieldWithPath("emails").type(ARRAY).description(emailListDescription),
        fieldWithPath("emails[].value").type(ARRAY).description(emailDescription),
        fieldWithPath("emails[].primary").type(BOOLEAN).description(emailPrimaryDescription),
        fieldWithPath("groups").type(ARRAY).description(groupDescription),
        fieldWithPath("groups[].value").type(STRING).description(groupIdDescription),
        fieldWithPath("groups[].display").type(STRING).description(groupDisplayNameDescription),
        fieldWithPath("groups[].type").type(STRING).description(membershipTypeDescription),
        fieldWithPath("approvals").type(ARRAY).description(approvalsListDescription),
        fieldWithPath("approvals[].userId").type(STRING).description(approvalUserIdDescription),
        fieldWithPath("approvals[].clientId").type(STRING).description(approvalClientIdDescription),
        fieldWithPath("approvals[].scope").type(STRING).description(approvalScopeDescription),
        fieldWithPath("approvals[].status").type(STRING).description(approvalStatusDescription),
        fieldWithPath("approvals[].lastUpdatedAt").type(STRING).description(approvalsLastUpdatedAtDescription),
        fieldWithPath("approvals[].expiresAt").type(STRING).description(approvalsExpiresAtDescription),
        fieldWithPath("active").type(BOOLEAN).description(userActiveDescription),
        fieldWithPath("verified").type(BOOLEAN).description(userVerifiedDescription),
        fieldWithPath("origin").type(STRING).description(userOriginDescription),
        fieldWithPath("zoneId").type(STRING).description(userZoneIdDescription),
        fieldWithPath("passwordLastModified").type(STRING).description(passwordLastModifiedDescription),
        fieldWithPath("externalId").type(STRING).description(externalIdDescription),
        fieldWithPath("meta").type(STRING).description("SCIM object meta data."),
        fieldWithPath("meta.version").type(NUMBER).description("Object version."),
        fieldWithPath("meta.lastModified").type(STRING).description("Object last modified date."),
        fieldWithPath("meta.created").type(STRING).description("Object created date."),
    };

    private final String scimFilterDescription = "SCIM filter for searching";
    private final String sortByDescription = "Sorting field name, like email or id";
    private final String sortOrderDescription = "Sort order, ascending/descending";
    private final String countDescription = "Max number of results to be returned";
    ParameterDescriptor[] searchUsersParameters = {
        parameterWithName("filter").optional(null).description(scimFilterDescription).attributes(key("type").value(STRING)),
        parameterWithName("sortBy").optional("created").description(sortByDescription).attributes(key("type").value(STRING)),
        parameterWithName("sortOrder").optional("ascending").description(sortOrderDescription).attributes(key("type").value(STRING)),
        parameterWithName("startIndex").optional("1").description(startIndexDescription).attributes(key("type").value(NUMBER)),
        parameterWithName("count").optional("100").description(countDescription).attributes(key("type").value(NUMBER)),
    };

    private String scimReadToken;
    private String scimWriteToken;
    ScimUser user;
    ScimUserProvisioning userProvisioning;
    TestClient testClient;

    @Before
    public void setUp() throws Exception {
        userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        testClient = new TestClient(getMockMvc());

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

        user = createScimUserObject();
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

    protected ScimUser createScimUserObject() {
        String username = new RandomValueStringGenerator().generate()+"@test.org";
        ScimUser user = new ScimUser(null, username, "given name", "family name");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        user.setExternalId("test-user");
        return user;
    }

    @Test
    public void test_Find_Users() throws Exception {


        Snippet responseFields = responseFields(searchResponseFields);
        Snippet requestParameters = requestParameters(searchUsersParameters);

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
                         requestParameters,
                         responseFields
                )
            );
    }

    @Test
    public void test_Create_User() throws Exception {

        user = createScimUserObject();

        getMockMvc().perform(
            RestDocumentationRequestBuilders.post("/Users")
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer "+scimWriteToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(user))
        )
            .andExpect(status().isCreated())
            .andDo(
                document("{ClassName}/{methodName}",
                         preprocessRequest(prettyPrint()),
                         preprocessResponse(prettyPrint()),
                         requestHeaders(
                             headerWithName("Authorization").description("Access token with scim.read or uaa.admin required")
                         ),
                         createFields,
                         responseFields(createResponse)
                )
            );
    }

    @Test
    public void test_Update_User() throws Exception {
        ApprovalStore store = getWebApplicationContext().getBean(ApprovalStore.class);
        Approval approval = new Approval()
            .setUserId(user.getId())
            .setStatus(Approval.ApprovalStatus.DENIED)
            .setScope("uaa.user")
            .setClientId("identity")
            .setExpiresAt(new Date(System.currentTimeMillis()+30000))
            .setLastUpdatedAt(new Date(System.currentTimeMillis()+30000));
        store.addApproval(approval);
        user.setGroups(Collections.emptyList());

        getMockMvc().perform(
            RestDocumentationRequestBuilders.put("/Users/{userId}", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer "+scimWriteToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
                .content(JsonUtils.writeValueAsString(user))
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                         preprocessRequest(prettyPrint()),
                         preprocessResponse(prettyPrint()),
                         pathParameters(parameterWithName("userId").description(userIdDescription)),
                         requestHeaders(
                             headerWithName("Authorization").description("Access token with scim.read or uaa.admin required"),
                             headerWithName("If-Match").description("The version of the SCIM object to be updated. Wildcard (*) accepted.")
                         ),
                         updateFields,
                         responseFields(updateResponse)
                )
            );
    }

    @Test
    public void test_Delete_User() throws Exception {
        ApprovalStore store = getWebApplicationContext().getBean(ApprovalStore.class);
        Approval approval = new Approval()
            .setUserId(user.getId())
            .setStatus(Approval.ApprovalStatus.APPROVED)
            .setScope("uaa.user")
            .setClientId("identity")
            .setExpiresAt(new Date(System.currentTimeMillis()+30000))
            .setLastUpdatedAt(new Date(System.currentTimeMillis()+30000));
        store.addApproval(approval);

        getMockMvc().perform(
            RestDocumentationRequestBuilders.delete("/Users/{userId}", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer "+scimWriteToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                         preprocessRequest(prettyPrint()),
                         preprocessResponse(prettyPrint()),
                         pathParameters(parameterWithName("userId").description(userIdDescription)),
                         requestHeaders(
                             headerWithName("Authorization").description("Access token with scim.read or uaa.admin required"),
                             headerWithName("If-Match").optional().description("The version of the SCIM object to be deleted. Optional.")
                         ),

                         responseFields(updateResponse)
                )
            );
    }


    @Test
    public void test_Change_Password() throws Exception {
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("secret");
        request.setPassword("newsecret");

        String myToken = MockMvcUtils.utils().getUserOAuthAccessToken(getMockMvc(), "app", "appclientsecret", user.getUserName(), "secret", null, null, true);

        getMockMvc().perform(
            RestDocumentationRequestBuilders.put("/Users/{userId}/password", user.getId())
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer "+myToken)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .header("If-Match", user.getVersion())
                .content(JsonUtils.writeValueAsString(request))
        )
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                         preprocessRequest(prettyPrint()),
                         preprocessResponse(prettyPrint()),
                         pathParameters(parameterWithName("userId").description(userIdDescription)),
                         requestHeaders(
                             headerWithName("Authorization").description("Access token with scim.read or uaa.admin required")
                         ),
                         requestFields(
                             fieldWithPath("oldPassword").required().description("Old password.").type(STRING),
                             fieldWithPath("password").required().description("New password.").type(STRING)
                         ),
                         responseFields(
                             fieldWithPath("status").description("Will be 'ok' if password changed successfully."),
                             fieldWithPath("message").description("Will be 'password updated' if password changed successfully.")
                         )
                )
            );
    }

    @Test
    public void getUserVerificationLink() throws Exception {
        String accessToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");

        String email = "joel@example.com";
        ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
        joel.setVerified(false);
        joel.addEmail(email);
        joel = userProvisioning.createUser(joel, "pas5Word");

        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/Users/{userId}/verify-link", joel.getId())
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

        MockHttpServletRequestBuilder get = RestDocumentationRequestBuilders.get("/Users/{userId}/verify", billy.getId())
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
