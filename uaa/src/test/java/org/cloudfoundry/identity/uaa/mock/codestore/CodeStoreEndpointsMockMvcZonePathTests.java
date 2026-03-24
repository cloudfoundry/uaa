package org.cloudfoundry.identity.uaa.mock.codestore;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
@EnabledIfZonePathsEnabled
class CodeStoreEndpointsMockMvcZonePathTests {

    private String loginToken;

    @Value("${disableInternalUserManagement:false}")
    private boolean disableInternalUserManagement;

    private TestClient testClient;
    private MockMvc mockMvc;
    private JdbcTemplate jdbcTemplate;
    private JdbcExpiringCodeStore jdbcExpiringCodeStore;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @BeforeEach
    void setUp(@Autowired JdbcTemplate jdbcTemplate,
               @Autowired JdbcExpiringCodeStore jdbcExpiringCodeStore,
               @Autowired MockMvc mockMvc,
               @Autowired TestClient testClient) throws Exception {
        this.jdbcTemplate = jdbcTemplate;
        this.jdbcExpiringCodeStore = jdbcExpiringCodeStore;
        this.mockMvc = mockMvc;
        this.testClient = testClient;
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        jdbcTemplate.update("DELETE FROM expiring_code_store");
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.update("DELETE FROM expiring_code_store");
    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void generateCode(String url) throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").exists())
                .andExpect(jsonPath("$.expiresAt").value(ts.getTime()))
                .andExpect(jsonPath("$.data").value("{}"));

    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void generateCodeWithInvalidScope(String url) throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.read");

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void generateCodeAnonymous(String url) throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void generateCodeWithNullData(String url) throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void generateCodeWithNullExpiresAt(String url) throws Exception {
        ExpiringCode code = new ExpiringCode(null, null, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void generateCodeWithExpiresAtInThePast(String url) throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() - 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void retrieveCode(String url) throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                .header("Authorization", "Bearer " + loginToken)
                .accept(MediaType.APPLICATION_JSON);

        result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        ExpiringCode rc1 = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        assertThat(rc1).isEqualTo(rc);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void retrieveCodeThatIsExpired(String url) throws Exception {
        Timestamp ts = new Timestamp(Long.MAX_VALUE);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);
        expireAllCodes();
        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                .header("Authorization", "Bearer " + loginToken)
                .accept(MediaType.APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/Codes", "/Codes/"})
    void codeThatIsExpiredIsDeletedOnCreateOfNewCode(String url) throws Exception {
        Timestamp ts = new Timestamp(Long.MAX_VALUE);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        expireAllCodes();

        ts = new Timestamp(Long.MAX_VALUE);
        code = new ExpiringCode(null, ts, "{}", null);
        requestBody = JsonUtils.writeValueAsString(code);
        post = post(url)
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        MvcResult createResult = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        ExpiringCode newCode = JsonUtils.readValue(createResult.getResponse().getContentAsString(), ExpiringCode.class);
        long now = System.currentTimeMillis();
        // Resilient to race: cleanup may not run if another thread won the CAS. Assert exactly one non-expired
        // code exists and it is the one we just created (so we pass whether or not the throttled cleanup ran).
        Integer nonExpiredCount = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM expiring_code_store WHERE expiresat > ?",
                Integer.class,
                now);
        assertThat(nonExpiredCount).isOne();
        String storedCode = jdbcTemplate.queryForObject(
                "SELECT code FROM expiring_code_store WHERE expiresat > ?",
                String.class,
                now);
        assertThat(storedCode).isEqualTo(newCode.getCode());
    }

    @Nested
    @DefaultTestContext
    class WithCustomExpirationInterval {
        long priorExpirationInterval;

        @BeforeEach
        void setUp() throws Exception {
            // TODO: Why is this here?
            Timestamp ts = new Timestamp(Long.MAX_VALUE);
            ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
            String requestBody = JsonUtils.writeValueAsString(code);
            MockHttpServletRequestBuilder post = post("/Codes")
                    .header("Authorization", "Bearer " + loginToken)
                    .contentType(APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .content(requestBody);

            MvcResult result = mockMvc.perform(post)
                    .andExpect(status().isCreated())
                    .andReturn();

            JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

            expireAllCodes();
            priorExpirationInterval = jdbcExpiringCodeStore.getExpirationInterval();
        }

        @AfterEach
        void tearDown() {
            jdbcExpiringCodeStore.setExpirationInterval(priorExpirationInterval);
        }

        @ParameterizedTest
        @ValueSource(strings = {"/Codes", "/Codes/"})
        void verifyExpirationIntervalWorks(String url) throws Exception {
            jdbcExpiringCodeStore.setExpirationInterval(10000000);
            Timestamp ts = new Timestamp(System.currentTimeMillis() + 1000);
            ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
            String requestBody = JsonUtils.writeValueAsString(code);
            MockHttpServletRequestBuilder post = post(url)
                    .header("Authorization", "Bearer " + loginToken)
                    .contentType(APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .content(requestBody);

            mockMvc.perform(post)
                    .andExpect(status().isCreated())
                    .andReturn();

            assertThat(jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class)).isEqualTo(2);
        }
    }

    @Nested
    @DefaultTestContext
    class CodesZonePathSupport {

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void codes_endpoint_responds_for_zone_path(ZoneResolutionMode mode) throws Exception {
            String subdomain = "codeszone" + System.nanoTime();
            UaaClientDetails loginClient = new UaaClientDetails("login", "", "oauth.login", "client_credentials", "", "http://redirect");
            loginClient.setClientSecret("loginsecret");
            MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, loginClient, IdentityZoneHolder.getCurrentZoneId());

            Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
            ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
            String requestBody = JsonUtils.writeValueAsString(code);

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/Codes")
                            .contentType(APPLICATION_JSON)
                            .accept(MediaType.APPLICATION_JSON)
                            .content(requestBody))
                    .andDo(print())
                    .andExpect(status().isUnauthorized());
        }
    }

    private void expireAllCodes() {
        jdbcExpiringCodeStore.setExpirationInterval(0);
        Timestamp expired = new Timestamp(System.currentTimeMillis() - 5000);
        jdbcTemplate.update("update expiring_code_store set expiresat=?", expired.getTime());
    }

}
