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
package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class InvitationsEndpointDocs extends InjectedMockContextTest {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String domain;
    private String clientId;
    private String clientSecret;
    private String authorities;
    String token;

    @Before
    public void setup() throws Exception {
        String adminToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin", null);
        domain = generator.generate().toLowerCase()+".com";
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        authorities = "scim.read,scim.invite";
        utils().createClient(getMockMvc(), adminToken, clientId, clientSecret, null, Arrays.asList("scim.invite"), Arrays.asList(new String[]{"client_credentials"}), authorities);
        token = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), clientId, clientSecret, "scim.invite", null, true);
    }

    @Test
    public void inviteUsers() throws Exception {
        String[] emails = new String[] {"user1@"+domain, "user2@"+domain};
        String redirectUri = "example.com";

        InvitationsRequest invitationsRequest = new InvitationsRequest(emails);
        String requestBody = JsonUtils.writeValueAsString(invitationsRequest);

        Snippet requestFields = requestFields(
                fieldWithPath("emails").attributes(key("constraints").value("Required")).description("User is invited by providing an email address. More than one email addresses can be provided.")
        );

        Snippet requestParameters = requestParameters(
                parameterWithName("client_id").attributes(key("constraints").value("Optional"), key("type").value(STRING)).description("A unique string representing the registration information provided by the client"),
                parameterWithName("redirect_uri").attributes(key("constraints").value("Required"), key("type").value(STRING)).description("The user will be redirected to this uri, when user accepts the invitation. The redirect_uri will be validated against allowed redirect_uri for the client.")
        );

        Snippet responseFields = responseFields(
                fieldWithPath("new_invites[].email").type(STRING).description("Primary email id of the invited user"),
                fieldWithPath("new_invites[].userId").type(STRING).description("A unique string for the invited user"),
                fieldWithPath("new_invites[].origin").type(STRING).description("Unique alias of the provider"),
                fieldWithPath("new_invites[].success").type(BOOLEAN).description("Flag to determine whether the invitation was sent successfully"),
                fieldWithPath("new_invites[].errorCode").optional().type(STRING).description("Error code in case of failure to send invitation"),
                fieldWithPath("new_invites[].errorMessage").optional().type(STRING).description("Error message in case of failure to send invitation"),
                fieldWithPath("new_invites[].inviteLink").type(STRING).description("Invitation link to invite users"),
                fieldWithPath("failed_invites").type(ARRAY).description("List of invites having exception in sending the invitation")
        );

        getMockMvc().perform(post("/invite_users?" + String.format("%s=%s&%s=%s", CLIENT_ID, clientId, REDIRECT_URI, redirectUri))
                .header("Authorization","Bearer "+token)
                .contentType(APPLICATION_JSON)
                .content(requestBody)
        ).andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `scim.invite`"),
                                headerWithName(IdentityZoneSwitchingFilter.HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a zone_id."),
                                headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin scope/token, indicates what zone this request goes to by supplying a subdomain.")
                        ),
                        requestParameters,
                        requestFields,
                        responseFields));
    }

}
