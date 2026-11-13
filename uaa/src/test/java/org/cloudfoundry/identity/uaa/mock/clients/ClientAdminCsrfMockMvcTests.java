package org.cloudfoundry.identity.uaa.mock.clients;

import jakarta.servlet.http.Cookie;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class ClientAdminCsrfMockMvcTests {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TestClient testClient;
    @Autowired
    private UaaTokenServices tokenServices;

    private String adminToken;
    private UaaClientDetails client;
    private boolean clientCreated;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.admin");
        client = new UaaClientDetails(UUID.randomUUID().toString(), null, "uaa.none", "client_credentials", "uaa.none");
        client.setClientSecret("secret");
    }

    @AfterEach
    void removeCreatedClient() throws Exception {
        if (clientCreated) {
            mockMvc.perform(delete("/oauth/clients/" + client.getClientId())
                            .header(AUTHORIZATION, "Bearer " + adminToken))
                    .andExpect(status().isOk());
        }
    }

    @ParameterizedTest
    @CsvSource({
            "POST, /oauth/clients",
            "POST, /oauth/clients/",
            "PUT, /oauth/clients/example",
            "DELETE, /oauth/clients/example",
            "PUT, /oauth/clients/example/secret",
            "PUT, /oauth/clients/example/clientjwt",
            "POST, /oauth/clients/tx",
            "PUT, /oauth/clients/tx",
            "DELETE, /oauth/clients/tx"
    })
    void mutationWithoutBearerHeader_requiresCsrf(String method, String path) throws Exception {
        var response = mockMvc.perform(request(HttpMethod.valueOf(method), path)
                        .param("access_token", adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden())
                .andReturn().getResponse();

        assertThat(response.getContentAsString()).contains("CSRF");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Basic YWRtaW46YWRtaW5zZWNyZXQ=", "Bearer", "Bearer ", "Bearer    "})
    void nonBearerOrEmptyHeader_doesNotBypassCsrf(String authorization) throws Exception {
        var response = mockMvc.perform(post("/oauth/clients")
                        .header(AUTHORIZATION, authorization)
                        .param("access_token", adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden())
                .andReturn().getResponse();

        assertThat(response.getContentAsString()).contains("CSRF");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bearer ", "bearer ", "BEARER ", "Bearer"})
    void bearerHeader_allowsCreationWithoutCsrf(String scheme) throws Exception {
        var result = mockMvc.perform(post("/oauth/clients")
                        .header(AUTHORIZATION, scheme + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated())
                .andReturn();

        clientCreated = true;
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    void bearerAmongMultipleHeaders_allowsCreationWithoutCsrf() throws Exception {
        mockMvc.perform(post("/oauth/clients")
                        .header(AUTHORIZATION, "Basic YWRtaW46YWRtaW5zZWNyZXQ=", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());
        clientCreated = true;
    }

    @Test
    void invalidBearerToken_isNotAuthorized() throws Exception {
        mockMvc.perform(post("/oauth/clients")
                        .header(AUTHORIZATION, "Bearer invalid-token")
                        .param("access_token", adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void accessTokenParameterWithMatchingCsrf_allowsCreationWithoutSession(boolean csrfAsParameter) throws Exception {
        var createRequest = post("/oauth/clients")
                .param("access_token", adminToken)
                .cookie(new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf-token"))
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        if (csrfAsParameter) {
            createRequest.param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf-token");
        } else {
            createRequest.header(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME, "csrf-token");
        }
        var result = mockMvc.perform(createRequest)
                .andExpect(status().isCreated())
                .andReturn();

        clientCreated = true;
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    void mismatchedCsrfToken_isRejected() throws Exception {
        mockMvc.perform(post("/oauth/clients")
                        .param("access_token", adminToken)
                        .cookie(new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf-token"))
                        .header(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME, "wrong-token")
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void adminSessionWithoutBearerToken_isRejected(boolean includeCsrf) throws Exception {
        var session = new MockHttpSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new SecurityContextImpl(tokenServices.loadAuthentication(adminToken)));

        var createRequest = post("/oauth/clients")
                .session(session)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        if (includeCsrf) {
            createRequest.cookie(new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "csrf-token"))
                    .header(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_HEADER_NAME, "csrf-token");
        }
        var response = mockMvc.perform(createRequest)
                .andExpect(status().isForbidden())
                .andReturn().getResponse();

        assertThat(response.getContentAsString()).contains(includeCsrf ? "insufficient_scope" : "CSRF");
    }

    @Test
    void readWithAccessTokenParameter_doesNotRequireCsrf() throws Exception {
        mockMvc.perform(get("/oauth/clients").param("access_token", adminToken))
                .andExpect(status().isOk());
    }
}
