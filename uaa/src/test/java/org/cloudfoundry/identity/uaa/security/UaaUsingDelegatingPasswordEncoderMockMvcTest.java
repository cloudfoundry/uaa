package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class UaaUsingDelegatingPasswordEncoderMockMvcTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("INSERT INTO oauth_client_details (client_id, client_secret, authorized_grant_types, authorities) VALUES ('client_id_with_noop', '{noop}password', 'client_credentials', 'amazing.powers')");
        jdbcTemplate.execute("INSERT INTO oauth_client_details (client_id, client_secret, authorized_grant_types, authorities) VALUES ('client_id_with_bcrypt', '{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG', 'client_credentials', 'amazing.powers')");
        jdbcTemplate.execute("INSERT INTO oauth_client_details (client_id, client_secret, authorized_grant_types, authorities) VALUES ('client_id_with_no_algorithm_id', 'password', 'client_credentials', 'amazing.powers')");
        jdbcTemplate.execute("INSERT INTO oauth_client_details (client_id, client_secret, authorized_grant_types, authorities) VALUES ('client_id_with_no_password', NULL, 'client_credentials', 'amazing.powers')");
        jdbcTemplate.execute("INSERT INTO oauth_client_details (client_id, client_secret, authorized_grant_types, authorities) VALUES ('client_id_with_empty_password', '{noop}', 'client_credentials', 'amazing.powers')");
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.execute("delete from oauth_client_details");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "client_id_with_noop",
            "client_id_with_bcrypt"
    })
    void getClientCredentialsTokenWithValidPassword(String clientId) throws Exception {
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .param("client_id", clientId)
                .param("client_secret", "password")
                .param("grant_type", "client_credentials"))
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "client_id_with_empty_password"
    })
    void tryToGetTokenWithEmtpyPasswordMustFail(String clientId) throws Exception {
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .param("client_id", clientId)
                .param("client_secret", "")
                .param("grant_type", "client_credentials"))
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "client_id_with_no_password"
    })
    void tryToGetTokenWithEmtpyPasswordFails(String clientId) throws Exception {
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .param("client_id", clientId)
                .param("client_secret", "")
                .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tryToGetTokenWithInvalidPasswordFails() throws Exception {
        mockMvc.perform(post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .param("client_id", "client_id_with_no_algorithm_id")
                .param("client_secret", "password")
                .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized());
    }
}
