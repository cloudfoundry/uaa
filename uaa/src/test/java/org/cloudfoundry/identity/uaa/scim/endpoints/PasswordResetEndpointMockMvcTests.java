package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class PasswordResetEndpointMockMvcTests {

    private String loginToken;
    private ScimUser scimUser;
    private String adminToken;
    private AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();

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
        scimUser = new ScimUser(null, new AlphanumericRandomValueStringGenerator().generate() + "@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
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
        assertThat(expiringCode.getIntent()).isEqualTo(ExpiringCodeType.AUTOLOGIN.name());
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
        });
        assertThat(data)
                .isNotNull()
                .containsEntry("user_id", scimUser.getId())
                .containsEntry("username", scimUser.getUserName())
                .containsEntry(OAuth2Utils.CLIENT_ID, "login")
                .containsEntry(OriginKeys.ORIGIN, OriginKeys.UAA);
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
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
        });
        assertThat(data)
                .isNotNull()
                .containsEntry(OAuth2Utils.CLIENT_ID, "another-client");
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
                .andExpect(content().string(containsString("<input type=\"hidden\" name=\"email\" value=\"%s\"/>".formatted(email))))
                .andReturn();

        String resultingCodeString = getCodeFromPage(result);
        ExpiringCode resultingCode = jdbcExpiringCodeStore.retrieveCode(resultingCodeString, IdentityZoneHolder.get().getId());

        Map<String, String> resultingCodeData = JsonUtils.readValue(resultingCode.getData(), new TypeReference<Map<String, String>>() {
        });

        assertThat(resultingCodeData)
                .isNotNull()
                .containsEntry("client_id", "app")
                .containsEntry("username", email)
                .containsEntry("user_id", scimUser.getId())
                .containsEntry("redirect_uri", "redirect.example.com");
    }

    @Test
    void changePasswordDoWithClientidAndRedirecturi() throws Exception {
        String code = getExpiringCode(mockMvc, "app", "http://localhost:8080/app/", loginToken, scimUser);
        String email = scimUser.getUserName();

        MockHttpServletRequestBuilder get = get("/reset_password")
                .param("code", code)
                .param("email", email);

        MvcResult result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("<input type=\"hidden\" name=\"email\" value=\"%s\"/>".formatted(email))))
                .andReturn();

        String resultingCodeString = getCodeFromPage(result);

        MockHttpServletRequestBuilder post = post("/reset_password.do")
                .param("code", resultingCodeString)
                .param("email", email)
                .param("password", "newpass")
                .param("password_confirmation", "newpass")
                .with(cookieCsrf());

        mockMvc.perform(post)
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(webApplicationContext.getServletContext().getContextPath() + "/login?success=password_reset&form_redirect_uri=http://localhost:8080/app/"));

        post = post("/login.do")
                .param("username", scimUser.getUserName())
                .param("password", "newpass")
                .param("form_redirect_uri", "http://localhost:8080/app/")
                .with(cookieCsrf());

        mockMvc.perform(post)
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost:8080/app/"));
    }

    @Test
    void changePasswordWithInvalidPasswordReturnsErrorJson() throws Exception {
        String toolongpassword = new AlphanumericRandomValueStringGenerator(260).generate();
        String code = getExpiringCode(mockMvc, null, null, loginToken, scimUser);
        mockMvc.perform(post("/password_change")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .content("{\"code\":\"" + code + "\",\"new_password\":\"" + toolongpassword + "\"}"))
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
        MockMvcUtils.createClient(this.mockMvc, adminToken, zonifiedAdminClientId, zonifiedAdminClientSecret, Collections.singleton("oauth"), Collections.singletonList(zoneAdminScope), Arrays.asList("client_credentials", "password"), "uaa.none");
        String zoneAdminAccessToken = testClient.getUserOAuthAccessToken(zonifiedAdminClientId, zonifiedAdminClientSecret, scimUser.getUserName(), "secr3T", zoneAdminScope);

        ScimUser userInZone = new ScimUser(null, new AlphanumericRandomValueStringGenerator().generate() + "@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
        userInZone.setPrimaryEmail(userInZone.getUserName());
        userInZone.setPassword("secr3T");
        userInZone = MockMvcUtils.createUserInZone(mockMvc, adminToken, userInZone, "", identityZone.getId());

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
        Pattern codePattern = Pattern.compile("<input type=\"hidden\" name=\"code\" value=\"([A-Za-z0-9\\_\\-]+)\"/>");
        Matcher codeMatcher = codePattern.matcher(result.getResponse().getContentAsString());

        assertThat(codeMatcher.find()).isTrue();

        return codeMatcher.group(1);
    }
}
