package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.RemoteUserAuthentication;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;
import java.io.Serial;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class PasscodeMockMvcTests {
    private CaptureSecurityContextFilter captureSecurityContextFilter;
    private UaaPrincipal marissa;

    @Autowired
    WebApplicationContext webApplicationContext;
    @Autowired
    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        FilterChainProxy filterChainProxy = (FilterChainProxy) webApplicationContext.getBean(SPRING_SECURITY_FILTER_CHAIN);
        if (captureSecurityContextFilter == null) {
            captureSecurityContextFilter = new CaptureSecurityContextFilter();
            UaaFilterChain chain = webApplicationContext.getBean("tokenEndpointSecurityForPasscodes", UaaFilterChain.class);
            chain.getFilters().add(captureSecurityContextFilter);
            UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
            marissa = new UaaPrincipal(db.retrieveUserByName("marissa", OriginKeys.UAA));
            webApplicationContext.getBean(JdbcExpiringCodeStore.class).setGenerator(new RandomValueStringGenerator(32));
        }
    }

    @AfterEach
    void clearSecContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void loginUsingPasscodeWithUaaToken() throws Exception {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest());
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<>(), details);
        final MockSecurityContext mockSecurityContext = new MockSecurityContext(uaaAuthentication);

        SecurityContextHolder.setContext(mockSecurityContext);
        MockHttpSession session = new MockHttpSession();

        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                mockSecurityContext
        );

        MockHttpServletRequestBuilder get = get("/passcode")
                .accept(APPLICATION_JSON)
                .session(session);

        String passcode = JsonUtils.readValue(
                mockMvc.perform(get)
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(),
                String.class);

        mockSecurityContext.setAuthentication(null);
        session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                mockSecurityContext
        );

        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64("cf:".getBytes()));
        MockHttpServletRequestBuilder post = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("passcode", passcode)
                .param("response_type", "token");

        Map<String, Object> accessToken =
                JsonUtils.readValueAsMap(
                        mockMvc.perform(post)
                                .andExpect(status().isOk())
                                .andReturn().getResponse().getContentAsString());
        assertThat(accessToken).containsEntry("token_type", "bearer")
                .containsKey("access_token")
                .containsKey("refresh_token");
        String[] scopes = ((String) accessToken.get("scope")).split(" ");
        assertThat(Arrays.asList(scopes)).contains("uaa.user", "scim.userids", "password.write", "cloud_controller.write", "openid", "cloud_controller.read");

        Authentication authentication = captureSecurityContextFilter.getAuthentication();
        assertThat(authentication).isInstanceOf(OAuth2Authentication.class);
        assertThat(((OAuth2Authentication) authentication).getUserAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.getPrincipal()).isInstanceOf(UaaPrincipal.class);
        assertThat(((UaaPrincipal) authentication.getPrincipal()).getOrigin()).isEqualTo(marissa.getOrigin());
    }

    @Test
    void loginUsingPasscodeWithUnknownToken() throws Exception {
        RemoteUserAuthentication userAuthentication = new RemoteUserAuthentication(
                marissa.getId(),
                marissa.getName(),
                marissa.getEmail(),
                new ArrayList<>()
        );
        final MockSecurityContext mockSecurityContext = new MockSecurityContext(userAuthentication);

        SecurityContextHolder.setContext(mockSecurityContext);
        MockHttpSession session = new MockHttpSession();

        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                mockSecurityContext
        );

        MockHttpServletRequestBuilder get = get("/passcode")
                .accept(APPLICATION_JSON)
                .session(session);

        mockMvc.perform(get)
                .andExpect(status().isForbidden());
    }

    @Test
    void loginUsingOldPasscode() throws Exception {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest());
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<>(), details);
        final MockSecurityContext mockSecurityContext = new MockSecurityContext(uaaAuthentication);

        SecurityContextHolder.setContext(mockSecurityContext);
        MockHttpSession session = new MockHttpSession();

        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                mockSecurityContext
        );

        MockHttpServletRequestBuilder get = get("/passcode")
                .accept(APPLICATION_JSON)
                .session(session);

        String passcode = JsonUtils.readValue(
                mockMvc.perform(get)
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(),
                String.class);

        // Get another code, which should expire the old.
        mockMvc.perform(get("/passcode")
                .accept(APPLICATION_JSON)
                .session(session));

        mockSecurityContext.setAuthentication(null);
        session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                mockSecurityContext
        );

        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64("cf:".getBytes()));
        MockHttpServletRequestBuilder post = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("passcode", passcode)
                .param("response_type", "token");

        mockMvc.perform(post)
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginUsingInvalidPasscode() throws Exception {
        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64("cf:".getBytes()));
        MockHttpServletRequestBuilder post = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("response_type", "token")
                .param("passcode", "no_such_passcode");

        String content = mockMvc.perform(post)
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        assertThat(content).contains("Invalid passcode");
    }

    @Test
    void loginUsingNoPasscode() throws Exception {
        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64("cf:".getBytes()));
        MockHttpServletRequestBuilder post = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("response_type", "token")
                .param("passcode", "");

        String content = mockMvc.perform(post)
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        assertThat(content).contains("Passcode information is missing.");
    }

    @Test
    void passcodeReturnSpecialCharacters() {
        // NOTE: This test is flaky but passes on retry
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest());
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<>(), details);
        MockSecurityContext mockSecurityContext = new MockSecurityContext(uaaAuthentication);

        SecurityContextHolder.setContext(mockSecurityContext);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, mockSecurityContext);

        // try for up to 15 seconds to get a passcode with - or _
        await().atMost(15, SECONDS).untilAsserted(() -> {
            MockHttpServletRequestBuilder get = get("/passcode").accept(APPLICATION_JSON).session(session);

            String passcode = JsonUtils.readValue(mockMvc.perform(get)
                            .andExpect(status().isOk())
                            .andReturn()
                            .getResponse()
                            .getContentAsString(),
                    String.class);

            assertThat(passcode).as("Passcode information is missing - or _")
                    .containsAnyOf("-", "_")
                    .matches("[1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\\-_]*");
        });
    }

    public static class MockSecurityContext implements SecurityContext {
        @Serial
        private static final long serialVersionUID = -1386535243513362694L;

        private Authentication authentication;

        MockSecurityContext(Authentication authentication) {
            this.authentication = authentication;
        }

        @Override
        public Authentication getAuthentication() {
            return this.authentication;
        }

        @Override
        public void setAuthentication(Authentication authentication) {
            this.authentication = authentication;
        }
    }

    public static class CaptureSecurityContextFilter extends GenericFilterBean {
        private Authentication authentication;

        public Authentication getAuthentication() {
            return authentication;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            authentication = SecurityContextHolder.getContext().getAuthentication();
            chain.doFilter(request, response);
        }
    }
}
