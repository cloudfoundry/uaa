package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CsrfPostProcessor.csrf;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DefaultTestContext
class PasswordResetEndpointMockMvcTests {

    private String loginToken;
    private ScimUser scimUser;
    private String adminToken;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @Autowired
    private TestClient testClient;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private WebApplicationContext webApplicationContext;
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private JdbcExpiringCodeStore jdbcExpiringCodeStore;

    @BeforeEach
    void setUp() throws Exception {
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", null);
        scimUser = new ScimUser(null, new RandomValueStringGenerator().generate()+"@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
        scimUser.setPrimaryEmail(scimUser.getUserName());
        scimUser.setPassword("secr3T");
        scimUser = MockMvcUtils.createUser(mockMvc, adminToken, scimUser);
    }

    @AfterEach
    void resetGenerator() {
        jdbcExpiringCodeStore.setGenerator(new RandomValueStringGenerator(24));
    }

    @Test
    void changePasswordIsSuccessful() throws Exception {

        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = jdbcExpiringCodeStore;
        store.setGenerator(generator);

        String code = getExpiringCode(mockMvc, null, null, loginToken, scimUser);
        MockHttpServletRequestBuilder post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"" + code + "\",\"new_password\":\"new_secr3T\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(scimUser.getUserName()))
                .andExpect(jsonPath("$.code").value("test" + generator.counter.get()));

        ExpiringCode expiringCode = store.retrieveCode("test" + generator.counter.get(), IdentityZoneHolder.get().getId());
        assertThat(expiringCode.getIntent(), is(ExpiringCodeType.AUTOLOGIN.name()));
        Map<String,String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
        assertThat(data, is(not(nullValue())));
        assertThat(data.get("user_id"), is(scimUser.getId()));
        assertThat(data.get("username"), is(scimUser.getUserName()));
        assertThat(data.get(OAuth2Utils.CLIENT_ID), is("login"));
        assertThat(data.get(OriginKeys.ORIGIN), is(OriginKeys.UAA));
    }

    @Test
    void changePasswordIsSuccessfulWithOverridenClientId() throws Exception {

        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = jdbcExpiringCodeStore;
        store.setGenerator(generator);

        String code = getExpiringCode(mockMvc, "another-client", null, loginToken, scimUser);
        MockHttpServletRequestBuilder post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"" + code + "\",\"new_password\":\"new_secr3T\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(scimUser.getUserName()))
                .andExpect(jsonPath("$.code").value("test" + generator.counter.get()));

        ExpiringCode expiringCode = store.retrieveCode("test" + generator.counter.get(), IdentityZoneHolder.get().getId());
        Map<String,String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String,String>>() {});
        assertThat(data, is(not(nullValue())));
        assertThat(data.get(OAuth2Utils.CLIENT_ID), is("another-client"));
    }

    @Test
    void changePasswordWithClientidAndRedirecturi() throws Exception {
        String code = getExpiringCode(mockMvc, "app", "redirect.example.com", loginToken, scimUser);
        String email = scimUser.getUserName();

        MockHttpServletRequestBuilder get = get("/reset_password")
            .param("code", code)
            .param("email", email);

        MvcResult result = mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(String.format("<input type=\"hidden\" name=\"email\" value=\"%s\"/>", email))))
            .andReturn();

        String resultingCodeString = getCodeFromPage(result);
        ExpiringCode resultingCode = jdbcExpiringCodeStore.retrieveCode(resultingCodeString, IdentityZoneHolder.get().getId());

        Map<String, String> resultingCodeData = JsonUtils.readValue(resultingCode.getData(), new TypeReference<Map<String, String>>() {
        });

        assertThat(resultingCodeData, is(not(nullValue())));
        assertEquals("app", resultingCodeData.get("client_id"));
        assertEquals(email, resultingCodeData.get("username"));
        assertEquals(scimUser.getId(), resultingCodeData.get("user_id"));
        assertEquals("redirect.example.com", resultingCodeData.get("redirect_uri"));
    }

    @Test
    void changePasswordDoWithClientidAndRedirecturi() throws Exception {
        String code = getExpiringCode(mockMvc, "app", "http://localhost:8080/app/", loginToken, scimUser);
        String email = scimUser.getUserName();

        MockHttpSession session = new MockHttpSession();

        MockHttpServletRequestBuilder get = get("/reset_password")
            .session(session)
            .param("code", code)
            .param("email", email);

        MvcResult result = mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString(String.format("<input type=\"hidden\" name=\"email\" value=\"%s\"/>", email))))
            .andReturn();

        String resultingCodeString = getCodeFromPage(result);

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .param("code", resultingCodeString)
            .param("email", email)
            .param("password", "newpass")
            .param("password_confirmation", "newpass")
            .with(csrf(session));

        mockMvc.perform(post)
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl(webApplicationContext.getServletContext().getContextPath() +"/login?success=password_reset&form_redirect_uri=http://localhost:8080/app/"));

        post = post("/login.do")
            .param("username", scimUser.getUserName())
            .param("password", "newpass")
            .param("form_redirect_uri", "http://localhost:8080/app/")
            .with(csrf(session));

        mockMvc.perform(post)
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("http://localhost:8080/app/"));
    }

    @Test
    void changePasswordWithInvalidPasswordReturnsErrorJson() throws Exception {
        String toolongpassword = new RandomValueStringGenerator(260).generate();
        String code = getExpiringCode(mockMvc, null, null, loginToken, scimUser);
        mockMvc.perform(post("/password_change")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"" + code + "\",\"new_password\":\""+toolongpassword+"\"}"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_password"))
            .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."));
    }

    @Test
    void changePasswordReturnsUnprocessableEntityNewPasswordSameAsOld() throws Exception {
        // make sure password is the same as old
        resetPassword(mockMvc, loginToken, scimUser);

        String code = getExpiringCode(mockMvc, null, null, loginToken, scimUser);
        MockHttpServletRequestBuilder post = post("/password_change")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"" + code + "\",\"new_password\":\"d3faultPassword\"}")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_password"))
            .andExpect(jsonPath("$.message").value("Your new password cannot be the same as the old password."));
    }

    @Test
    void uaaAdminCanChangePassword() throws Exception {
        MvcResult mvcResult = mockMvc.perform(post("/password_resets")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(scimUser.getUserName())
            .accept(APPLICATION_JSON))
            .andExpect(status().isCreated()).andReturn();
        String responseString = mvcResult.getResponse().getContentAsString();
        String code = Objects.requireNonNull(JsonUtils.readValue(responseString, new TypeReference<Map<String, String>>() {
        })).get("code");

        mockMvc.perform(post("/password_change")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"" + code + "\",\"new_password\":\"new-password\"}")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user_id").exists())
            .andExpect(jsonPath("$.username").value(scimUser.getUserName()));
    }

    @Test
    void zoneAdminCanResetsAndChangePassword() throws Exception {
        String subDomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subDomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = result.getIdentityZone();
        String zoneAdminScope = "zones." + identityZone.getId() + ".admin";

        ScimUser scimUser = MockMvcUtils.createAdminForZone(mockMvc, adminToken, zoneAdminScope, IdentityZoneHolder.get().getId());

        String zonifiedAdminClientId = generator.generate().toLowerCase();
        String zonifiedAdminClientSecret = generator.generate().toLowerCase();
        MockMvcUtils.createClient(this.mockMvc, adminToken, zonifiedAdminClientId , zonifiedAdminClientSecret, Collections.singleton("oauth"), Collections.singletonList(zoneAdminScope), Arrays.asList("client_credentials", "password"), "uaa.none");
        String zoneAdminAccessToken = testClient.getUserOAuthAccessToken(zonifiedAdminClientId, zonifiedAdminClientSecret, scimUser.getUserName(), "secr3T", zoneAdminScope);

        ScimUser userInZone = new ScimUser(null, new RandomValueStringGenerator().generate()+"@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
        userInZone.setPrimaryEmail(userInZone.getUserName());
        userInZone.setPassword("secr3T");
        userInZone = MockMvcUtils.createUserInZone(mockMvc, adminToken, userInZone, "",identityZone.getId());

        mockMvc.perform(
            post("/password_resets")
                .header("Authorization", "Bearer " + zoneAdminAccessToken)
                .header(HEADER, identityZone.getId())
                .contentType(APPLICATION_JSON)
                .content(userInZone.getPrimaryEmail())
                .accept(APPLICATION_JSON))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.user_id").exists())
            .andExpect(jsonPath("$.code").isNotEmpty());
    }

    private static String getExpiringCode(MockMvc mockMvc, String clientId, String redirectUri, String loginToken, ScimUser scimUser) throws Exception {
        MockHttpServletRequestBuilder post = post("/password_resets")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .param("client_id", clientId)
            .param("redirect_uri", redirectUri)
            .param("response_type", "code")
            .content(scimUser.getUserName())
            .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(post)
            .andExpect(status().isCreated())
            .andReturn();

        String responseString = result.getResponse().getContentAsString();
        Map<String, String> response = new HashMap<>(Objects.requireNonNull(JsonUtils.readValue(responseString, new TypeReference<Map<String, String>>() {
        })));
        return response.get("code");
    }

    private static void resetPassword(MockMvc mockMvc, String loginToken, ScimUser scimUser) throws Exception {
        String code = getExpiringCode(mockMvc, null, null, loginToken, scimUser);
        MockHttpServletRequestBuilder post = post("/password_change")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"" + code + "\",\"new_password\":\"d3faultPassword\"}")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user_id").exists())
            .andExpect(jsonPath("$.username").value(scimUser.getUserName()));
    }

    private static String getCodeFromPage(MvcResult result) throws UnsupportedEncodingException {
        Pattern codePattern = Pattern.compile("<input type=\"hidden\" name=\"code\" value=\"([A-Za-z0-9]+)\"/>");
        Matcher codeMatcher = codePattern.matcher(result.getResponse().getContentAsString());

        assertTrue(codeMatcher.find());

        return codeMatcher.group(1);
    }
}
