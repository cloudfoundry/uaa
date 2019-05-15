package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.RemoteUserAuthentication;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class PasscodeMockMvcTests {
    private static String USERNAME = "marissa";

    private CaptureSecurityContextFilter captureSecurityContextFilter;
    private UaaPrincipal marissa;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp(@Autowired WebApplicationContext webApplicationContext, @Autowired MockMvc mockMvc) {
        this.mockMvc = mockMvc;

        FilterChainProxy filterChainProxy = (FilterChainProxy) webApplicationContext.getBean("org.springframework.security.filterChainProxy");
        if (captureSecurityContextFilter == null) {
            captureSecurityContextFilter = new CaptureSecurityContextFilter();

            List<SecurityFilterChain> chains = filterChainProxy.getFilterChains();
            for (SecurityFilterChain chain : chains) {

                if (chain instanceof DefaultSecurityFilterChain) {
                    DefaultSecurityFilterChain dfc = (DefaultSecurityFilterChain) chain;
                    if (dfc.getRequestMatcher() instanceof UaaRequestMatcher) {
                        UaaRequestMatcher matcher = (UaaRequestMatcher) dfc.getRequestMatcher();
                        if (matcher.toString().contains("passcodeTokenMatcher")) {
                            dfc.getFilters().add(captureSecurityContextFilter);
                            break;
                        }
                    }
                }
            }
            UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
            marissa = new UaaPrincipal(db.retrieveUserByName(USERNAME, OriginKeys.UAA));
        }
    }

    @AfterEach
    void clearSecContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void testLoginUsingPasscodeWithSamlToken() throws Exception {
        ExpiringUsernameAuthenticationToken et = new ExpiringUsernameAuthenticationToken(USERNAME, null);
        UaaAuthentication auth = new LoginSamlAuthenticationToken(marissa, et).getUaaAuthentication(
                Collections.emptyList(),
                Collections.emptySet(),
                new LinkedMultiValueMap<>()
        );
        final MockSecurityContext mockSecurityContext = new MockSecurityContext(auth);

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

        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64(("cf:").getBytes()));
        MockHttpServletRequestBuilder post = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("passcode", passcode)
                .param("response_type", "token");


        Map accessToken =
                JsonUtils.readValue(
                        mockMvc.perform(post)
                                .andExpect(status().isOk())
                                .andReturn().getResponse().getContentAsString(),
                        Map.class);
        assertEquals("bearer", accessToken.get("token_type"));
        assertNotNull(accessToken.get("access_token"));
        assertNotNull(accessToken.get("refresh_token"));
        String[] scopes = ((String) accessToken.get("scope")).split(" ");
        assertThat(Arrays.asList(scopes), containsInAnyOrder("uaa.user", "scim.userids", "password.write", "cloud_controller.write", "openid", "cloud_controller.read"));

        Authentication authentication = captureSecurityContextFilter.getAuthentication();
        assertNotNull(authentication);
        assertTrue(authentication instanceof OAuth2Authentication);
        assertTrue(((OAuth2Authentication) authentication).getUserAuthentication() instanceof UsernamePasswordAuthenticationToken);
        assertTrue(authentication.getPrincipal() instanceof UaaPrincipal);
        assertEquals(marissa.getOrigin(), ((UaaPrincipal) authentication.getPrincipal()).getOrigin());
    }

    @Test
    void testLoginUsingPasscodeWithUaaToken() throws Exception {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest());
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<GrantedAuthority>(), details);

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

        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64(("cf:").getBytes()));
        MockHttpServletRequestBuilder post = post("/oauth/token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("passcode", passcode)
                .param("response_type", "token");


        Map accessToken =
                JsonUtils.readValue(
                        mockMvc.perform(post)
                                .andExpect(status().isOk())
                                .andReturn().getResponse().getContentAsString(),
                        Map.class);
        assertEquals("bearer", accessToken.get("token_type"));
        assertNotNull(accessToken.get("access_token"));
        assertNotNull(accessToken.get("refresh_token"));
        String[] scopes = ((String) accessToken.get("scope")).split(" ");
        assertThat(Arrays.asList(scopes), containsInAnyOrder("uaa.user", "scim.userids", "password.write", "cloud_controller.write", "openid", "cloud_controller.read"));

        Authentication authentication = captureSecurityContextFilter.getAuthentication();
        assertNotNull(authentication);
        assertTrue(authentication instanceof OAuth2Authentication);
        assertTrue(((OAuth2Authentication) authentication).getUserAuthentication() instanceof UsernamePasswordAuthenticationToken);
        assertTrue(authentication.getPrincipal() instanceof UaaPrincipal);
        assertEquals(marissa.getOrigin(), ((UaaPrincipal) authentication.getPrincipal()).getOrigin());
    }

    @Test
    void testLoginUsingPasscodeWithUnknownToken() throws Exception {
        RemoteUserAuthentication userAuthentication = new RemoteUserAuthentication(
                marissa.getId(),
                marissa.getName(),
                marissa.getEmail(),
                new ArrayList<GrantedAuthority>()
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
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testLoginUsingOldPasscode() throws Exception {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest());
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<GrantedAuthority>(), details);

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

        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64(("cf:").getBytes()));
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
        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64(("cf:").getBytes()));
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
        assertThat(content, Matchers.containsString("Invalid passcode"));
    }

    @Test
    void loginUsingNoPasscode() throws Exception {
        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64(("cf:").getBytes()));
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
        assertThat(content, Matchers.containsString("Passcode information is missing."));
    }

    public static class MockSecurityContext implements SecurityContext {

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
