/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.password;

import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class PasswordChangeEndpointMockMvcTests extends InjectedMockContextTest {
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String passwordWriteToken;
    private String adminToken;

    @Before
    public void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret scim.write clients.admin");
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();

        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, null, "client_credentials", "password.write");
        clientDetails.setClientSecret(clientSecret);

        utils().createClient(getMockMvc(), adminToken, clientDetails);

        passwordWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"password.write");
    }

    @Test
    public void changePassword_withInvalidPassword_returnsErrorJson() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("secr3T");
        request.setPassword(new RandomValueStringGenerator(260).generate());
        getMockMvc().perform(put("/Users/" + user.getId() + "/password").header("Authorization", "Bearer " + passwordWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_password"))
                .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."));
    }

    @Test
    public void changePassword_NewPasswordSameAsOld_ReturnsUnprocessableEntityWithJsonError() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("secr3T");
        request.setPassword("secr3T");
        getMockMvc().perform(put("/Users/" + user.getId() + "/password").header("Authorization", "Bearer " + passwordWriteToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request)))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_password"))
            .andExpect(jsonPath("$.message").value("Your new password cannot be the same as the old password."));
    }

    @Test
    public void changePassword_SuccessfullyChangePassword() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("secr3T");
        request.setPassword("n3wAw3som3Passwd");

        MockHttpServletRequestBuilder put = put("/Users/" + user.getId() +"/password")
                .header("Authorization", "Bearer " + passwordWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
            .accept(APPLICATION_JSON);

        getMockMvc().perform(put)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.message").value("password updated"));
    }

    @Test
    public void changePassword_Resets_Session() throws Exception {
        ScimUser user = createUser();

        MockHttpSession session = new MockHttpSession();
        session.invalidate();
        MockHttpSession afterLoginSession = (MockHttpSession) getMockMvc().perform(post("/login.do")
            .with(cookieCsrf())
            .session(session)
            .accept(TEXT_HTML_VALUE)
            .param("username", user.getUserName())
            .param("password", "secr3T"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn().getRequest().getSession(false);

        assertNotNull(afterLoginSession);
        assertNotNull(afterLoginSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));

        MockHttpSession afterPasswordChange = (MockHttpSession) getMockMvc().perform(post("/change_password.do")
            .session(afterLoginSession)
            .with(csrf())
            .accept(TEXT_HTML_VALUE)
            .param("current_password", "secr3T")
            .param("new_password", "secr3T1")
            .param("confirm_password", "secr3T1"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile"))
            .andReturn().getRequest().getSession(false);

        assertTrue(afterLoginSession.isInvalid());
        assertNotNull(afterPasswordChange);
        assertNotNull(afterPasswordChange.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        assertNotSame(afterLoginSession, afterPasswordChange);

    }

    @Test
    public void changePassword_Resets_All_Sessions() throws Exception {
        ScimUser user = createUser();

        MockHttpSession session = new MockHttpSession();
        MockHttpSession afterLoginSessionA = (MockHttpSession) getMockMvc().perform(post("/login.do")
            .with(cookieCsrf())
            .session(session)
            .accept(TEXT_HTML_VALUE)
            .param("username", user.getUserName())
            .param("password", "secr3T"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn().getRequest().getSession(false);

        session = new MockHttpSession();
        MockHttpSession afterLoginSessionB = (MockHttpSession) getMockMvc().perform(post("/login.do")
            .with(cookieCsrf())
            .session(session)
            .accept(TEXT_HTML_VALUE)
            .param("username", user.getUserName())
            .param("password", "secr3T"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn().getRequest().getSession(false);


        assertNotNull(afterLoginSessionA.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        assertNotNull(afterLoginSessionB.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));

        getMockMvc().perform(get("/profile").session(afterLoginSessionB))
            .andExpect(status().isOk());

        Thread.sleep(1000 - (System.currentTimeMillis() % 1000) + 1);

        MockHttpSession afterPasswordChange = (MockHttpSession) getMockMvc().perform(post("/change_password.do")
            .session(afterLoginSessionA)
            .with(csrf())
            .accept(TEXT_HTML_VALUE)
            .param("current_password", "secr3T")
            .param("new_password", "secr3T1")
            .param("confirm_password", "secr3T1"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile"))
            .andReturn().getRequest().getSession(false);

        assertTrue(afterLoginSessionA.isInvalid());
        assertNotNull(afterPasswordChange);
        assertNotNull(afterPasswordChange.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        assertNotSame(afterLoginSessionA, afterPasswordChange);
        getMockMvc().perform(
            get("/profile")
                .session(afterLoginSessionB)
                .accept(TEXT_HTML))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));

    }

    private ScimUser createUser() throws Exception {
        String id = generator.generate();
        ScimUser user = new ScimUser(id, id + "user@example.com", "name", "familyname");
        user.addEmail(id + "user@example.com");
        user.setPassword("secr3T");
        return utils().createUser(getMockMvc(), adminToken, user);
    }
}
