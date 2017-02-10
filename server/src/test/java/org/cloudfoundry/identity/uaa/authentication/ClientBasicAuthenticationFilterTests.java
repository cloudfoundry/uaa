package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import static org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest.UsernamePasswordAuthentication;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import java.io.IOException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class ClientBasicAuthenticationFilterTests {
    private ClientBasicAuthenticationFilter filter;
    private IdentityZone testZone;

    private AuthenticationManager clientAuthenticationManager;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private LoginPolicy loginPolicy;
    private ClientDetailsService clientDetailsService;

    private static final String CREDENTIALS_HEADER_STRING =
                new String(Base64.getEncoder().encode("app:appclientsecret".getBytes()));

    @Before
    public void setUp() {
        clientAuthenticationManager = mock(AuthenticationManager.class);
        authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        filter = new ClientBasicAuthenticationFilter(clientAuthenticationManager,
                authenticationEntryPoint);

        loginPolicy = mock(LoginPolicy.class);

        clientDetailsService = mock(ClientDetailsService.class);

        filter.setLoginPolicy(loginPolicy);
        filter.setClientDetailsService(clientDetailsService);

        when(loginPolicy.isAllowed(anyString())).thenReturn(new LoginPolicy.Result(true, 3));

        testZone = new IdentityZone();
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,255,0,0,0,0,6));

        IdentityZoneHolder.set(testZone);
    }

    @After
    public void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    public void doesContinueWithFilterChain_IfClientSecretNotExpired() throws IOException, ServletException, ParseException {
        BaseClientDetails clientDetails = new BaseClientDetails("client-1", "none", "uaa.none", "client_credentials",
                "http://localhost:5000/uaadb" );

        Calendar previousDay = Calendar.getInstance();
        previousDay.roll(Calendar.DATE, -1);

        clientDetails.setAdditionalInformation(createTestAdditionalInformation(previousDay));

        when(clientDetailsService.loadClientByClientId(Mockito.matches("app"))).thenReturn(clientDetails);

        UsernamePasswordAuthentication authResult =
                new UsernamePasswordAuthentication("app","appclientsecret");
        authResult.setAuthenticated(true);
        when(clientAuthenticationManager.authenticate(any())).thenReturn(authResult);

        MockFilterChain chain = mock(MockFilterChain.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + CREDENTIALS_HEADER_STRING);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(clientAuthenticationManager).authenticate(any(Authentication.class));
    }

    @Test
    public void doesNotContinueWithFilterChain_IfClientSecretExpired() throws IOException, ServletException, ParseException {
        BaseClientDetails clientDetails = new BaseClientDetails("client-1", "none", "uaa.none", "client_credentials",
                               "http://localhost:5000/uaadb" );


        Calendar expiredDate = Calendar.getInstance();
        expiredDate.set(2016, 1, 1);
        clientDetails.setAdditionalInformation(createTestAdditionalInformation(expiredDate));

        when(clientDetailsService.loadClientByClientId(Mockito.matches("app"))).thenReturn(clientDetails);

        MockFilterChain chain = mock(MockFilterChain.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + CREDENTIALS_HEADER_STRING);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(authenticationEntryPoint).commence(any(request.getClass()), any(response.getClass()), any(BadCredentialsException.class));
        verifyNoMoreInteractions(chain);
    }

    private Map<String, Object> createTestAdditionalInformation(Calendar calendar) throws ParseException{
        Map<String,Object> additionalInformation = new HashMap<String,Object>();
        additionalInformation.put(ClientConstants.LAST_MODIFIED,
                new Timestamp(calendar.getTimeInMillis()));

        return additionalInformation;
    }
}