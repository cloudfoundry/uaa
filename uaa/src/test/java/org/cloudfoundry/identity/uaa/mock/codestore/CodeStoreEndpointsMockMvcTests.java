package org.cloudfoundry.identity.uaa.mock.codestore;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class CodeStoreEndpointsMockMvcTests {

    private String loginToken;

    @Value("${disableInternalUserManagement:false}")
    private boolean disableInternalUserManagement;

    private TestClient testClient;
    private MockMvc mockMvc;
    private JdbcTemplate jdbcTemplate;
    private JdbcExpiringCodeStore jdbcExpiringCodeStore;

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

    @Test
    void generateCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
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

    @Test
    void generateCodeWithInvalidScope() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.read");

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isForbidden());
    }

    @Test
    void generateCodeAnonymous() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isUnauthorized());
    }

    @Test
    void generateCodeWithNullData() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @Test
    void generateCodeWithNullExpiresAt() throws Exception {
        ExpiringCode code = new ExpiringCode(null, null, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @Test
    void generateCodeWithExpiresAtInThePast() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() - 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @Test
    void retrieveCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
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

    @Test
    void retrieveCodeThatIsExpired() throws Exception {
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

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);
        expireAllCodes();
        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                .header("Authorization", "Bearer " + loginToken)
                .accept(MediaType.APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void codeThatIsExpiredIsDeletedOnCreateOfNewCode() throws Exception {
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

        ts = new Timestamp(Long.MAX_VALUE);
        code = new ExpiringCode(null, ts, "{}", null);
        requestBody = JsonUtils.writeValueAsString(code);
        post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        assertThat(jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class)).isOne();
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

        @Test
        void verifyExpirationIntervalWorks() throws Exception {
            jdbcExpiringCodeStore.setExpirationInterval(10000000);
            Timestamp ts = new Timestamp(System.currentTimeMillis() + 1000);
            ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
            String requestBody = JsonUtils.writeValueAsString(code);
            MockHttpServletRequestBuilder post = post("/Codes")
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

    private void expireAllCodes() {
        jdbcExpiringCodeStore.setExpirationInterval(0);
        Timestamp expired = new Timestamp(System.currentTimeMillis() - 5000);
        jdbcTemplate.update("update expiring_code_store set expiresat=?", expired.getTime());
    }

}
