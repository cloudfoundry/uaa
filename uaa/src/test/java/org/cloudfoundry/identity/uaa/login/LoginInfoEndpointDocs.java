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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.junit.Test;
import org.springframework.restdocs.snippet.Snippet;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.headerWithName;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class LoginInfoEndpointDocs extends InjectedMockContextTest {


    @Test
    public void info_endpoint_for_json() throws Exception {
        Snippet requestParameters = requestParameters();

        Snippet responseFields = responseFields(
            fieldWithPath("app.version").type(STRING).description("The UAA version"),
            fieldWithPath("commit_id").type(STRING).description("The GIT sha for the UAA version"),
            fieldWithPath("timestamp").type(STRING).description("JSON timestamp for the commit of the UAA version"),
            fieldWithPath("idpDefinitions").type(OBJECT).description("A list of alias/url pairs of SAML IDP providers configured. Each url is the starting point to initiate the authentication process for the SAML identity provider."),
            fieldWithPath("links").type(OBJECT).description("A list of alias/url pairs of configured action URLs for the UAA"),
            fieldWithPath("links.login").type(STRING).description("The link to the login host alias of the UAA"),
            fieldWithPath("links.uaa").type(STRING).description("The link to the uaa alias host of the UAA"),
            fieldWithPath("links.passwd").type(STRING).description("The link to the 'Forgot Password' functionality. Can be external or internal to the UAA"),
            fieldWithPath("links.register").type(STRING).description("The link to the 'Create Account' functionality. Can be external or internal to the UAA"),
            fieldWithPath("entityID").type(STRING).description("The UAA is always a SAML service provider. This field contains the configured entityID"),
            fieldWithPath("prompts").type(OBJECT).description("A list of name/value pairs of configured prompts that the UAA will login a user. Format for each prompt is [type, display name] where type can be 'text' or 'password'"),
            fieldWithPath("prompts.username").type(ARRAY).description("Information about the username prompt."),
            fieldWithPath("prompts.password").type(ARRAY).description("Information about the password prompt."),
            fieldWithPath("prompts.passcode").optional().type(ARRAY).description("If a SAML identity provider is configured, this prompt contains a URL to where the user can initiate the SAML authentication flow."),
            fieldWithPath("zone_name").type(STRING).description("The name of the zone invoked"),
            fieldWithPath("showLoginLinks").optional(false).type(BOOLEAN).description("Set to true if there are SAML or OAUTH/OIDC providers with a visible link on the login page.")
        );

        Snippet requestHeaders = requestHeaders(
            headerWithName(ACCEPT).description("When set to accept " + APPLICATION_JSON_VALUE + " the server will return prompts and server info in JSON format.")
        );

        getMockMvc().perform(get("/info")
            .header(ACCEPT, APPLICATION_JSON_VALUE))
            .andExpect(status().isOk())
            .andDo(
                document("{ClassName}/{methodName}",
                         preprocessResponse(prettyPrint()),
                         requestHeaders,
                         requestParameters,
                         responseFields)
            );
    }

    @Test
    public void user_ui_login() throws Exception {
        Snippet requestParameters = requestParameters(
            parameterWithName("username").required().type(STRING).description("The username of the user, sometimes the email address."),
            parameterWithName("password").required().type(STRING).description("The user's password"),
            parameterWithName("X-Uaa-Csrf").required().type(STRING).description("Automatically configured by the server upon /login. Must match the value of the X-Uaa-Csrf cookie.")
        );
        Snippet requestHeaders = requestHeaders(
            headerWithName("Cookie").required().type(STRING).description("Must contain the a value for the cookie X-Uaa-Csrf and that must match the request parameter of the same name")
        );

        getMockMvc().perform(
            post("/login.do")
                .with(cookieCsrf())
                .header("Cookie","X-Uaa-Csrf=12345a")
                .param("username", "marissa")
                .param("password", "koala")
                .param("X-Uaa-Csrf", "12345a"))
            .andDo(
                document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                requestHeaders,
                requestParameters))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));
    }


}
