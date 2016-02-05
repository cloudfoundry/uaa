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
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class PasswordResetEndpointMockMvcTests extends InjectedMockContextTest {

    private String loginToken;
    private ScimUser user;

    @Before
    public void setUp() throws Exception {
        TestClient testClient = new TestClient(getMockMvc());
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", null);
        user = new ScimUser(null, new RandomValueStringGenerator().generate()+"@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = MockMvcUtils.utils().createUser(getMockMvc(), adminToken, user);
    }

    @Test
    public void changePassword_isSuccessful() throws Exception {

        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        String code = getExpiringCode(null, null);
        MockHttpServletRequestBuilder post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"" + code + "\",\"new_password\":\"new_secr3T\"}")
                .accept(APPLICATION_JSON);

        getMockMvc().perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(user.getUserName()))
                .andExpect(jsonPath("$.code").value("test" + generator.counter.get()));

        ExpiringCode expiringCode = store.retrieveCode("test" + generator.counter.get());
        Map<String,String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
        assertThat(data.get("user_id"), is(user.getId()));
        assertThat(data.get("username"), is(user.getUserName()));
        assertThat(data.get(OAuth2Utils.CLIENT_ID), is("login"));
        assertThat(data.get(OriginKeys.ORIGIN), is(OriginKeys.UAA));
        assertThat(data.get("action"), is(ExpiringCodeType.AUTOLOGIN.name()));
    }

    @Test
    public void changePassword_isSuccessful_withOverridenClientId() throws Exception {

        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        String code = getExpiringCode("another-client", null);
        MockHttpServletRequestBuilder post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"" + code + "\",\"new_password\":\"new_secr3T\"}")
                .accept(APPLICATION_JSON);

        getMockMvc().perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(user.getUserName()))
                .andExpect(jsonPath("$.code").value("test" + generator.counter.get()));

        ExpiringCode expiringCode = store.retrieveCode("test" + generator.counter.get());
        Map<String,String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
        assertThat(data.get(OAuth2Utils.CLIENT_ID), is("another-client"));
    }

    @Test
    public void changePassword_with_clientid_and_redirecturi() throws Exception {
        String code = getExpiringCode("app", "redirect.example.com");
        String email = user.getUserName();

        MockHttpServletRequestBuilder get = get("/reset_password")
            .param("code", code)
            .param("email", email);

        MvcResult result = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(String.format("<input type=\"hidden\" name=\"email\" value=\"%s\" />", email))))
            .andReturn();

        String resultingCodeString = getCodeFromPage(result);
        ExpiringCodeStore expiringCodeStore = (ExpiringCodeStore) getWebApplicationContext().getBean("codeStore");
        ExpiringCode resultingCode = expiringCodeStore.retrieveCode(resultingCodeString);

        Map<String, String> resultingCodeData = JsonUtils.readValue(resultingCode.getData(), new TypeReference<Map<String, String>>() {
        });

        assertEquals("app", resultingCodeData.get("client_id"));
        assertEquals(email, resultingCodeData.get("username"));
        assertEquals(user.getId(), resultingCodeData.get("user_id"));
        assertEquals("redirect.example.com", resultingCodeData.get("redirect_uri"));
    }

    @Test
    public void changePassword_do_with_clientid_and_redirecturi() throws Exception {
        String code = getExpiringCode("app", "http://localhost:8080/app/");
        String email = user.getUserName();

        MockHttpServletRequestBuilder get = get("/reset_password")
            .param("code", code)
            .param("email", email);

        MvcResult result = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(String.format("<input type=\"hidden\" name=\"email\" value=\"%s\" />", email))))
            .andReturn();

        String resultingCodeString = getCodeFromPage(result);

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .param("code", resultingCodeString)
            .param("email", email)
            .param("password", "newpass")
            .param("password_confirmation", "newpass")
            .with(csrf());

        getMockMvc().perform(post)
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("http://localhost:8080/app/"));
    }

    @Test
    public void changePassword_withInvalidPassword_returnsErrorJson() throws Exception {
        String toolongpassword = new RandomValueStringGenerator(260).generate();
        String code = getExpiringCode(null, null);
        getMockMvc().perform(post("/password_change")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"" + code + "\",\"new_password\":\""+toolongpassword+"\"}"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_password"))
            .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."));
    }

    @Test
    public void changePassword_ReturnsUnprocessableEntity_NewPasswordSameAsOld() throws Exception {
        // make sure password is the same as old
        resetPassword("d3faultPassword");

        String code = getExpiringCode(null, null);
        MockHttpServletRequestBuilder post = post("/password_change")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"" + code + "\",\"new_password\":\"d3faultPassword\"}")
            .accept(APPLICATION_JSON);

        getMockMvc().perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_password"))
            .andExpect(jsonPath("$.message").value("Your new password cannot be the same as the old password."));
    }

    private String getExpiringCode(String clientId, String redirectUri) throws Exception {
        MockHttpServletRequestBuilder post = post("/password_resets")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .param("client_id", clientId)
            .param("redirect_uri", redirectUri)
            .content(user.getUserName())
            .accept(APPLICATION_JSON);

        MvcResult result = getMockMvc().perform(post)
            .andExpect(status().isCreated())
            .andReturn();

        String responseString = result.getResponse().getContentAsString();
        Map<String,String> response = JsonUtils.readValue(responseString, new TypeReference<Map<String, String>>() {
        });
        return response.get("code");
    }

    private void resetPassword(String defaultPassword) throws Exception {
        String code = getExpiringCode(null, null);
        MockHttpServletRequestBuilder post = post("/password_change")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"" + code + "\",\"new_password\":\"" + defaultPassword + "\"}")
            .accept(APPLICATION_JSON);

        getMockMvc().perform(post)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user_id").exists())
            .andExpect(jsonPath("$.username").value(user.getUserName()));
    }

    private String getCodeFromPage(MvcResult result) throws UnsupportedEncodingException {
        Pattern codePattern = Pattern.compile("<input type=\"hidden\" name=\"code\" value=\"([A-Za-z0-9]+)\" />");
        Matcher codeMatcher = codePattern.matcher(result.getResponse().getContentAsString());

        assertTrue(codeMatcher.find());

        String pageCode = codeMatcher.group(1).toString();
        return pageCode;
    }
}
