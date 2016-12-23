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

import org.cloudfoundry.identity.uaa.account.UaaResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.PredictableGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.servlet.http.Cookie;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.account.UaaResetPasswordService.FORGOT_PASSWORD_INTENT_PREFIX;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ResetPasswordControllerMockMvcTests extends InjectedMockContextTest {

    private ExpiringCodeStore codeStore;

    @Before
    public void initResetPasswordTest() throws Exception {
        codeStore = getWebApplicationContext().getBean(ExpiringCodeStore.class);
    }

    @After
    public void resetGenerator() throws Exception {
        getWebApplicationContext().getBean(JdbcExpiringCodeStore.class).setGenerator(new RandomValueStringGenerator(24));
    }


    @Test
    public void testResettingAPasswordUsingUsernameToEnsureNoModification() throws Exception {

        List<ScimUser> users = getWebApplicationContext().getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        PasswordChange change = new PasswordChange(users.get(0).getId(), users.get(0).getUserName(), users.get(0).getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);

        MvcResult mvcResult = getMockMvc().perform(createChangePasswordRequest(users.get(0), code, true))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getId(), equalTo(users.get(0).getId()));
        assertThat(principal.getName(), equalTo(users.get(0).getUserName()));
        assertThat(principal.getEmail(), equalTo(users.get(0).getPrimaryEmail()));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    @Test
    public void testResettingPasswordUpdatesLastLogonTime() throws Exception {
        List<ScimUser> users = getWebApplicationContext().getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        Long lastLogonBeforeReset = users.get(0).getLastLogonTime();
        PasswordChange change = new PasswordChange(users.get(0).getId(), users.get(0).getUserName(), users.get(0).getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);

        MvcResult mvcResult = getMockMvc().perform(createChangePasswordRequest(users.get(0), code, true))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn();

        ScimUser userMarissa = getWebApplicationContext().getBean(ScimUserProvisioning.class).retrieve(users.get(0).getId());
        assertNotNull(userMarissa.getLastLogonTime());
        if(lastLogonBeforeReset != null) {
            assertTrue(userMarissa.getLastLogonTime() > lastLogonBeforeReset);
        }
    }

    @Test
    public void testResettingAPasswordFailsWhenUsernameChanged() throws Exception {

        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
        PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + 50000), null);

        String formerUsername = user.getUserName();
        user.setUserName("newusername");
        user = userProvisioning.update(user.getId(), user);
        try {
            getMockMvc().perform(createChangePasswordRequest(users.get(0), code, true))
                .andExpect(status().isUnprocessableEntity());
        } finally {
            user.setUserName(formerUsername);
            userProvisioning.update(user.getId(), user);
        }
    }

    @Test
    public void testResettingAPassword_whenCodeIsValid_rendersTheChangePasswordForm() throws Exception {

        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        String token = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), token, user);

        PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");

        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + 50000), FORGOT_PASSWORD_INTENT_PREFIX + user.getId());

        MockHttpServletRequestBuilder get = get("/reset_password?code={code}", code.getCode())
            .accept(MediaType.TEXT_HTML);

        String content = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        String renderedCode = findInRenderedPage(content, "\\<input type=\\\"hidden\\\" name=\\\"code\\\" value=\\\"(.*?)\\\" \\/\\>");
        assertEquals(renderedCode, code.getCode());

        String renderedEmail = findInRenderedPage(content, "\\<input type=\\\"hidden\\\" name=\\\"email\\\" value=\\\"(.*?)\\\" \\/\\>");
        assertEquals(renderedEmail, user.getPrimaryEmail());


        getMockMvc().perform(createChangePasswordRequest(user, renderedCode, true, "secret1", "secret1"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));
    }

    private String findInRenderedPage(String renderedContent, String regexPattern) {
        Pattern expiringCodePattern = Pattern.compile(regexPattern);
        Matcher matcher = expiringCodePattern.matcher(renderedContent);
        assertTrue(matcher.find());
        return matcher.group(1);
    }

    @Test
    public void new_code_overwrite_old_code_for_repeated_request() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        String token = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), token, user);


        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);
        JdbcTemplate template = getWebApplicationContext().getBean(JdbcTemplate.class);
        String intent = FORGOT_PASSWORD_INTENT_PREFIX+user.getId();

        getMockMvc().perform(post("/forgot_password.do")
                                 .param("email", user.getUserName()))
            .andExpect(redirectedUrl("email_sent?code=reset_password"));

        getMockMvc().perform(post("/forgot_password.do")
                                 .param("email", user.getUserName()))
            .andExpect(redirectedUrl("email_sent?code=reset_password"));

        assertEquals(1, (int)template.queryForObject("select count(*) from expiring_code_store where intent=?", new Object[] {intent}, Integer.class));

    }

    @Test
    public void redirectToSavedRequest_ifPresent() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        String token = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), token, user);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new DefaultSavedRequest(new MockHttpServletRequest(), new PortResolverImpl()) {
            @Override
            public String getRedirectUrl() {
                return "http://test/redirect/oauth/authorize";
            }
            @Override
            public String[] getParameterValues(String name) {
                if ("client_id".equals(name)) {
                    return new String[] {"admin"};
                }
                return new String[0];
            }
            @Override public List<Cookie> getCookies() { return null; }
            @Override public String getMethod() { return null; }
            @Override public List<String> getHeaderValues(String name) { return null; }
            @Override
            public Collection<String> getHeaderNames() { return null; }
            @Override public List<Locale> getLocales() { return null; }
            @Override public Map<String, String[]> getParameterMap() { return null; }
        };
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);

        PredictableGenerator generator = new PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        getMockMvc().perform(post("/forgot_password.do")
                .session(session)
                .param("email", user.getUserName()))
                .andExpect(redirectedUrl("email_sent?code=reset_password"));

        getMockMvc().perform(createChangePasswordRequest(user, "test" + generator.counter.get(), true, "secret1", "secret1")
                .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test/redirect/oauth/authorize"))
                .andReturn();
    }

    @Test
    public void testResettingAPasswordFailsWhenPasswordChanged() throws Exception {
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname","familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        String token = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        user = MockMvcUtils.utils().createUser(getMockMvc(), token, user);
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        Thread.sleep(1000 - (System.currentTimeMillis() % 1000) + 10); //because password last modified is second only
        PasswordChange change = new PasswordChange(user.getId(), user.getUserName(), user.getPasswordLastModified(), "", "");
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + 50000), null);

        userProvisioning.changePassword(user.getId(), "secret", "secr3t");
        getMockMvc().perform(createChangePasswordRequest(user, code, true))
            .andExpect(status().isUnprocessableEntity());
    }

    @Test
    public void testResettingAPasswordNoCsrfParameter() throws Exception {
        List<ScimUser> users = getWebApplicationContext().getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ExpiringCode code = codeStore.generateCode(users.get(0).getId(), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);

        getMockMvc().perform(createChangePasswordRequest(users.get(0), code, false))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testResettingAPasswordUsingTimestampForUserModification() throws Exception {
        List<ScimUser> users = getWebApplicationContext().getBean(ScimUserProvisioning.class).query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        PasswordChange passwordChange = new PasswordChange(users.get(0).getId(), users.get(0).getUserName(), null, null, null);
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis()+ UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);

        MockHttpServletRequestBuilder post = createChangePasswordRequest(users.get(0), code,
            true, "newpassw0rD", "newpassw0rD");

        MvcResult mvcResult = getMockMvc().perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"))
            .andReturn();

        SecurityContext securityContext = (SecurityContext) mvcResult.getRequest().getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = securityContext.getAuthentication();
        assertThat(authentication.getPrincipal(), instanceOf(UaaPrincipal.class));
        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        assertThat(principal.getId(), equalTo(users.get(0).getId()));
        assertThat(principal.getName(), equalTo(users.get(0).getUserName()));
        assertThat(principal.getEmail(), equalTo(users.get(0).getPrimaryEmail()));
        assertThat(principal.getOrigin(), equalTo(OriginKeys.UAA));
    }

    @Test
    public void resetPassword_ReturnsUnprocessableEntity_NewPasswordSameAsOld() throws Exception {
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
        PasswordChange passwordChange = new PasswordChange(user.getId(), user.getUserName(), null, null, null);
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);
        getMockMvc().perform(createChangePasswordRequest(user, code, true, "d3faultPasswd", "d3faultPasswd"));

        code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);
        getMockMvc().perform(createChangePasswordRequest(user, code, true, "d3faultPasswd", "d3faultPasswd"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(request().attribute("message", equalTo("Your new password cannot be the same as the old password.")))
            .andExpect(request().attribute("code", equalTo(code.getCode())))
            .andExpect(request().attribute("email", equalTo(user.getPrimaryEmail())))
            .andExpect(forwardedUrl("/reset_password"));
    }

    @Test
    public void resetPassword_ReturnsUnprocessableEntity_NewPasswordNotAccordingToPolicy() throws Exception {

        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = getWebApplicationContext().getBean(IdentityProviderProvisioning.class).retrieveByOrigin(UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition currentDefinition = uaaProvider.getConfig();
        PasswordPolicy passwordPolicy = new PasswordPolicy();
        passwordPolicy.setMinLength(3);
        passwordPolicy.setMaxLength(20);
        uaaProvider.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
        getWebApplicationContext().getBean(IdentityProviderProvisioning.class).update(uaaProvider);

        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        List<ScimUser> users = userProvisioning.query("username eq \"marissa\"");
        assertNotNull(users);
        assertEquals(1, users.size());
        ScimUser user = users.get(0);
        PasswordChange passwordChange = new PasswordChange(user.getId(), user.getUserName(), null, null, null);
        ExpiringCode code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);
        getMockMvc().perform(createChangePasswordRequest(user, code, true, "d3faultPasswd", "d3faultPasswd"));

        code = codeStore.generateCode(JsonUtils.writeValueAsString(passwordChange), new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), null);
        getMockMvc().perform(createChangePasswordRequest(user, code, true, "a", "a"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(request().attribute("message", equalTo("Password must be at least 3 characters in length.")))
            .andExpect(request().attribute("code", equalTo(code.getCode())))
            .andExpect(request().attribute("email", equalTo(user.getPrimaryEmail())))
            .andExpect(forwardedUrl("/reset_password"));

        uaaProvider = getWebApplicationContext().getBean(IdentityProviderProvisioning.class).retrieveByOrigin(UAA, IdentityZone.getUaa().getId());
        uaaProvider.setConfig(currentDefinition);
        getWebApplicationContext().getBean(IdentityProviderProvisioning.class).update(uaaProvider);
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, ExpiringCode code, boolean useCSRF) throws Exception {
        return createChangePasswordRequest(user, code, useCSRF, "newpassw0rDl", "newpassw0rDl");
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, ExpiringCode code, boolean useCSRF, String password, String passwordConfirmation) throws Exception {
        return createChangePasswordRequest(user,code.getCode(),useCSRF, password,passwordConfirmation);
    }

    private MockHttpServletRequestBuilder createChangePasswordRequest(ScimUser user, String code, boolean useCSRF, String password, String passwordConfirmation) throws Exception {
        MockHttpServletRequestBuilder post = post("/reset_password.do");
        if (useCSRF) {
            post.with(csrf());
        }
        post.param("code", code)
            .param("email", user.getPrimaryEmail())
            .param("password", password)
            .param("password_confirmation", passwordConfirmation);
        return post;
    }
}
