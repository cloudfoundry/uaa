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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints.PASSWORD_RESET_LIFETIME;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ResetPasswordControllerMockMvcTests extends InjectedMockContextTest {

    ExpiringCodeStore codeStore;

    @Before
    public void initResetPasswordTest() throws Exception {
        codeStore = getWebApplicationContext().getBean(ExpiringCodeStore.class);
    }

    @Test
    public void testResettingAPasswordUsingUsernameToEnsureNoModification() throws Exception {

        List<ScimUser> users = getWebApplicationContext().getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        PasswordResetEndpoints.PasswordChange change = new PasswordResetEndpoints.PasswordChange();
        change.setUserId(users.get(0).getId());
        change.setUsername(users.get(0).getUserName());

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis()+ PASSWORD_RESET_LIFETIME));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .with(csrf())
            .param("code", code.getCode())
            .param("email", users.get(0).getPrimaryEmail())
            .param("password", "newpassword")
            .param("password_confirmation", "newpassword");

        MvcResult mvcResult = getMockMvc().perform(post)
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

        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
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
                .with(csrf())
                .param("code", code.getCode())
                .param("email", user.getPrimaryEmail())
                .param("password", "newpassword")
                .param("password_confirmation", "newpassword");

            getMockMvc().perform(post)
                .andExpect(status().isUnprocessableEntity());
        } finally {
            user.setUserName(formerUsername);
            userProvisioning.update(user.getId(), user);
        }
    }

    @Test
    public void testResettingAPasswordNoCsrfParameter() throws Exception {
        List<ScimUser> users = getWebApplicationContext().getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ExpiringCode code = codeStore.generateCode(users.get(0).getId(), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .param("code", code.getCode())
            .param("email", users.get(0).getPrimaryEmail())
            .param("password", "newpassword")
            .param("password_confirmation", "newpassword");

        getMockMvc().perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testResettingAPasswordUsingTimestampForUserModification() throws Exception {
        List<ScimUser> users = getWebApplicationContext().getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ExpiringCode code = codeStore.generateCode(users.get(0).getId(), new Timestamp(System.currentTimeMillis()+ PASSWORD_RESET_LIFETIME));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .with(csrf())
            .param("code", code.getCode())
            .param("email", users.get(0).getPrimaryEmail())
            .param("password", "newpassword")
            .param("password_confirmation", "newpassword");

        MvcResult mvcResult = getMockMvc().perform(post)
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
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
        ExpiringCode code = codeStore.generateCode(user.getId(), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .with(csrf())
            .param("code", code.getCode())
            .param("email", user.getPrimaryEmail())
            .param("password", "newpassword")
            .param("password_confirmation", "newpassword");

        if (Arrays.asList(getWebApplicationContext().getEnvironment().getActiveProfiles()).contains("mysql")) {
            Thread.sleep(1050);
        } else {
            Thread.sleep(50);
        }

        userProvisioning.update(user.getId(), user);

        getMockMvc().perform(post)
            .andExpect(status().isUnprocessableEntity());


    }
}
