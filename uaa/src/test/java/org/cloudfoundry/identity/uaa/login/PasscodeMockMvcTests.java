package org.cloudfoundry.identity.uaa.login;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Arrays;
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
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.login.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.support.XmlWebApplicationContext;
import org.springframework.web.filter.GenericFilterBean;

public class PasscodeMockMvcTests {

    private XmlWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private CaptureSecurityContextFilter captureSecurityContextFilter;

    private static String USERNAME = "marissa";
    private UaaPrincipal marissa;

    @After
    public void tearDown() throws Exception {
        webApplicationContext.destroy();
    }

    @Before
    public void setUp() throws Exception {

        MockEnvironment environment = new MockEnvironment();
        MockServletContext context = new MockServletContext();
        MockServletConfig config = new MockServletConfig(context);
        config.addInitParameter("environmentConfigDefaults", "uaa.yml,login.yml");
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletConfig(config);
        webApplicationContext.setEnvironment(environment);
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = (FilterChainProxy)webApplicationContext.getBean("org.springframework.security.filterChainProxy");
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
            .build();

        captureSecurityContextFilter = new CaptureSecurityContextFilter();

        List<SecurityFilterChain> chains = springSecurityFilterChain.getFilterChains();
        for (SecurityFilterChain chain : chains) {

            if (chain instanceof DefaultSecurityFilterChain) {
                DefaultSecurityFilterChain dfc = (DefaultSecurityFilterChain)chain;
                if (dfc.getRequestMatcher() instanceof UaaRequestMatcher) {
                    UaaRequestMatcher matcher = (UaaRequestMatcher)dfc.getRequestMatcher();
                    if (matcher.toString().contains("passcodeTokenMatcher")) {
                        dfc.getFilters().add(captureSecurityContextFilter);
                        break;
                    }
                }
            }
        }
        UaaUserDatabase db = webApplicationContext.getBean(UaaUserDatabase.class);
        marissa = new UaaPrincipal(db.retrieveUserByName(USERNAME, Origin.UAA));
    }

    @Test
    public void testLoginUsingPasscodeWithSamlToken() throws Exception {
        ExpiringUsernameAuthenticationToken et = new ExpiringUsernameAuthenticationToken(USERNAME, null);
        LoginSamlAuthenticationToken auth = new LoginSamlAuthenticationToken(marissa, et);
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

        String passcode = new ObjectMapper().readValue(
            mockMvc.perform(get)
            .andExpect(status().isOk())
            .andDo(print())
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
            .param("response_type", "token")
            .session(session);


        Map accessToken =
            new ObjectMapper().readValue(
                mockMvc.perform(post)
                    .andDo(print())
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString(),
                Map.class);
        assertEquals("bearer", accessToken.get("token_type"));
        assertNotNull(accessToken.get("access_token"));
        assertNotNull(accessToken.get("refresh_token"));
        String[] scopes = ((String) accessToken.get("scope")).split(" ");
        assertThat(Arrays.asList(scopes), containsInAnyOrder("scim.userids", "password.write", "cloud_controller.write", "openid", "cloud_controller.read"));

        Authentication authentication = captureSecurityContextFilter.getAuthentication();
        assertNotNull(authentication);
        assertTrue(authentication instanceof OAuth2Authentication);
        assertTrue(((OAuth2Authentication)authentication).getUserAuthentication() instanceof UsernamePasswordAuthenticationToken);
        assertTrue(authentication.getPrincipal() instanceof UaaPrincipal);
        assertEquals(marissa.getOrigin(), ((UaaPrincipal)authentication.getPrincipal()).getOrigin());

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