/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints.PASSWORD_RESET_LIFETIME;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ResetPasswordControllerMockMvcTests extends TestClassNullifier {

    static XmlWebApplicationContext webApplicationContext;

    private static MockMvc mockMvc;
    private static ExpiringCodeStore codeStore;

    @BeforeClass
    public static void initResetPasswordTest() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "login.yml,uaa.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();
        codeStore = webApplicationContext.getBean(ExpiringCodeStore.class);
    }

    @AfterClass
    public static void cleanUpAfterPasswordReset() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.destroy();
    }


    @Test
    public void testResettingAPasswordUsingUsernameToEnsureNoModification() throws Exception {

        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        PasswordResetEndpoints.PasswordChange change = new PasswordResetEndpoints.PasswordChange();
        change.setUserId(users.get(0).getId());
        change.setUsername(users.get(0).getUserName());

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis()+ PASSWORD_RESET_LIFETIME));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .param("code", code.getCode())
            .param("email", users.get(0).getPrimaryEmail())
            .param("password", "newpassword")
            .param("password_confirmation", "newpassword");

        MvcResult mvcResult = mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("home"))
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getId(), equalTo(users.get(0).getId()));
        assertThat(principal.getName(), equalTo(users.get(0).getUserName()));
        assertThat(principal.getEmail(), equalTo(users.get(0).getPrimaryEmail()));
        assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }

    @Test
    public void testResettingAPasswordFailsWhenUsernameChanged() throws Exception {

        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
        PasswordResetEndpoints.PasswordChange change = new PasswordResetEndpoints.PasswordChange();
        change.setUserId(user.getId());
        change.setUsername(user.getUserName());

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis()+50000));

        String formerUsername = user.getUserName();
        user.setUserName("newusername");
        user = userProvisioning.update(user.getId(), user);
        try {
            MockHttpServletRequestBuilder post = post("/reset_password.do")
                .param("code", code.getCode())
                .param("email", user.getPrimaryEmail())
                .param("password", "newpassword")
                .param("password_confirmation", "newpassword");

            mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity());
        } finally {
            user.setUserName(formerUsername);
            userProvisioning.update(user.getId(), user);
        }
    }

    @Test
    public void testResettingAPasswordUsingTimestampForUserModification() throws Exception {
        List<ScimUser> users = webApplicationContext.getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ExpiringCode code = codeStore.generateCode(users.get(0).getId(), new Timestamp(System.currentTimeMillis()+ PASSWORD_RESET_LIFETIME));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .param("code", code.getCode())
            .param("email", users.get(0).getPrimaryEmail())
            .param("password", "newpassword")
            .param("password_confirmation", "newpassword");

        MvcResult mvcResult = mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("home"))
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getId(), equalTo(users.get(0).getId()));
        assertThat(principal.getName(), equalTo(users.get(0).getUserName()));
        assertThat(principal.getEmail(), equalTo(users.get(0).getPrimaryEmail()));
        assertThat(principal.getOrigin(), equalTo(Origin.UAA));
    }

    @Test
    public void testResettingAPasswordUsingTimestampUserModified() throws Exception {
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
        ExpiringCode code = codeStore.generateCode(user.getId(), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .param("code", code.getCode())
            .param("email", user.getPrimaryEmail())
            .param("password", "newpassword")
            .param("password_confirmation", "newpassword");

        if (Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles()).contains("mysql")) {
            Thread.sleep(1050);
        } else {
            Thread.sleep(50);
        }

        userProvisioning.update(user.getId(), user);

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity());


    }
}
