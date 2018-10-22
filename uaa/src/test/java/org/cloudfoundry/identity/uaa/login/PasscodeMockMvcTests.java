package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.RemoteUserAuthentication;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventListenerRule;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.*;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class PasscodeMockMvcTests {
    @Rule
    public HoneycombAuditEventListenerRule honeycombAuditEventListenerRule = new HoneycombAuditEventListenerRule();

    @Autowired
    public WebApplicationContext webApplicationContext;
    private CaptureSecurityContextFilter captureSecurityContextFilter;

    private static String USERNAME = "marissa";
    private UaaPrincipal marissa;
    private MockMvc mockMvc;

    @After
    public void clearSecContext() {
        SecurityContextHolder.clearContext();
    }

    @Before
    public void setUp() throws Exception {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();


        FilterChainProxy filterChainProxy = (FilterChainProxy) webApplicationContext.getBean("org.springframework.security.filterChainProxy");
        if (captureSecurityContextFilter==null) {
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

    @Test
    public void testLoginUsingPasscodeWithSamlToken() throws Exception {
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
        assertTrue(((OAuth2Authentication)authentication).getUserAuthentication() instanceof UsernamePasswordAuthenticationToken);
        assertTrue(authentication.getPrincipal() instanceof UaaPrincipal);
        assertEquals(marissa.getOrigin(), ((UaaPrincipal)authentication.getPrincipal()).getOrigin());
    }

    @Test
    public void testLoginUsingPasscodeWithUaaToken() throws Exception {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest());
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<GrantedAuthority>(),details);

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
        assertTrue(((OAuth2Authentication)authentication).getUserAuthentication() instanceof UsernamePasswordAuthenticationToken);
        assertTrue(authentication.getPrincipal() instanceof UaaPrincipal);
        assertEquals(marissa.getOrigin(), ((UaaPrincipal)authentication.getPrincipal()).getOrigin());
    }

    @Test
    public void testLoginUsingPasscodeWithUnknownToken() throws Exception {
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
    public void testLoginUsingOldPasscode() throws Exception {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(new MockHttpServletRequest());
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<GrantedAuthority>(),details);

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
    public void loginUsingInvalidPasscode() throws Exception {
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
    public void loginUsingNoPasscode() throws Exception {
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

        public MockSecurityContext(Authentication authentication) {
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
