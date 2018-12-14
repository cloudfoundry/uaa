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

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventListenerRule;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class PasswordChangeEndpointMockMvcTests {
    @Rule
    public HoneycombAuditEventListenerRule honeycombAuditEventListenerRule = new HoneycombAuditEventListenerRule();

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String passwordWriteToken;
    private String adminToken;
    private String password;
    @Autowired
    public WebApplicationContext webApplicationContext;
    private TestClient testClient;
    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        password = "secret";
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        testClient = new TestClient(mockMvc);
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret scim.write clients.admin");
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();

        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, null, "client_credentials", "password.write");
        clientDetails.setClientSecret(clientSecret);

        utils().createClient(mockMvc, adminToken, clientDetails);

        passwordWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"password.write");
    }

    @Test
    public void changePassword_withInvalidPassword_returnsErrorJson() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(password);
        String tooLongPassword = new RandomValueStringGenerator(260).generate();
        request.setPassword(tooLongPassword);
        MockHttpServletRequestBuilder putRequest = put("/Users/" + user.getId() + "/password")
                                                      .header("Authorization", "Bearer " + passwordWriteToken)
                                                      .contentType(APPLICATION_JSON)
                                                      .content(JsonUtils.writeValueAsString(request));

        mockMvc.perform(putRequest)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_password"))
                .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."));
    }

    @Test
    public void changePassword_NewPasswordSameAsOld_ReturnsUnprocessableEntityWithJsonError() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(password);
        request.setPassword(password);
        mockMvc.perform(put("/Users/" + user.getId() + "/password").header("Authorization", "Bearer " + passwordWriteToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(request)))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_password"))
            .andExpect(jsonPath("$.message").value("Your new password cannot be the same as one in your recent password history."));
    }

    @Test
    public void changePassword_WithBadOldPassword_ReturnsUnauthorizedError() throws Exception {
        ScimUser user = createUser();
        String userToken = testClient.getUserOAuthAccessToken("cf", "", user.getUserName(), password, "password.write");

        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("wrongPassword");
        request.setPassword(password);
        mockMvc.perform(put("/Users/" + user.getId() + "/password")
          .header("Authorization", "Bearer " + userToken)
          .contentType(APPLICATION_JSON)
          .content(JsonUtils.writeValueAsString(request)))
          .andExpect(status().isUnauthorized())
          .andExpect(jsonPath("$.error_description").value("Old password is incorrect"))
          .andExpect(jsonPath("$.error").value("unauthorized"))
          ;
    }

    @Test
    public void changePassword_SuccessfullyChangePassword() throws Exception {
        ScimUser user = createUser();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(password);
        request.setPassword("n3wAw3som3Passwd");

        MockHttpServletRequestBuilder put = put("/Users/" + user.getId() +"/password")
                .header("Authorization", "Bearer " + passwordWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
            .accept(APPLICATION_JSON);

        mockMvc.perform(put)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.message").value("password updated"));
    }

    @Test
    public void changePassword_Resets_Session() throws Exception {
        ScimUser user = createUser();

        MockHttpSession session = new MockHttpSession();
        session.invalidate();
        MockHttpSession afterLoginSession = (MockHttpSession) mockMvc.perform(post("/login.do")
            .with(cookieCsrf())
            .session(session)
            .accept(TEXT_HTML_VALUE)
            .param("username", user.getUserName())
            .param("password", password))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn().getRequest().getSession(false);

        assertNotNull(afterLoginSession);
        assertNotNull(afterLoginSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));

        MockHttpSession afterPasswordChange = (MockHttpSession) mockMvc.perform(post("/change_password.do")
            .session(afterLoginSession)
            .with(cookieCsrf())
            .accept(TEXT_HTML_VALUE)
            .param("current_password", password)
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
        MockHttpSession afterLoginSessionA = (MockHttpSession) mockMvc.perform(post("/login.do")
            .with(cookieCsrf())
            .session(session)
            .accept(TEXT_HTML_VALUE)
            .param("username", user.getUserName())
            .param("password", password))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn().getRequest().getSession(false);

        session = new MockHttpSession();
        MockHttpSession afterLoginSessionB = (MockHttpSession) mockMvc.perform(post("/login.do")
            .with(cookieCsrf())
            .session(session)
            .accept(TEXT_HTML_VALUE)
            .param("username", user.getUserName())
            .param("password", password))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn().getRequest().getSession(false);


        assertNotNull(afterLoginSessionA.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        assertNotNull(afterLoginSessionB.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));

        mockMvc.perform(get("/profile").session(afterLoginSessionB))
            .andExpect(status().isOk());

        Thread.sleep(1000 - (System.currentTimeMillis() % 1000) + 1);

        MockHttpSession afterPasswordChange = (MockHttpSession) mockMvc.perform(post("/change_password.do")
            .session(afterLoginSessionA)
            .with(cookieCsrf())
            .accept(TEXT_HTML_VALUE)
            .param("current_password", password)
            .param("new_password", "secr3T1")
            .param("confirm_password", "secr3T1"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile"))
            .andReturn().getRequest().getSession(false);

        assertTrue(afterLoginSessionA.isInvalid());
        assertNotNull(afterPasswordChange);
        assertNotNull(afterPasswordChange.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        assertNotSame(afterLoginSessionA, afterPasswordChange);
        mockMvc.perform(
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
        user.setPassword(password);
        return utils().createUser(mockMvc, adminToken, user);
    }
}
