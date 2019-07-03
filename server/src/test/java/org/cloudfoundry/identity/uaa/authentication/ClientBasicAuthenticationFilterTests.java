package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest.UsernamePasswordAuthentication;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ClientBasicAuthenticationFilterTests {
    private static final String CREDENTIALS_HEADER_STRING =
            new String(Base64.getEncoder().encode("app:appclientsecret".getBytes()));

    private ClientBasicAuthenticationFilter filter;
    private AuthenticationManager clientAuthenticationManager;
    private ClientDetailsService clientDetailsService;

    @BeforeEach
    void setUp() {
        tearDown();
        clientAuthenticationManager = mock(AuthenticationManager.class);
        AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        clientDetailsService = mock(ClientDetailsService.class);

        filter = new ClientBasicAuthenticationFilter(clientAuthenticationManager, authenticationEntryPoint);
        filter.setClientDetailsService(clientDetailsService);

        IdentityZone testZone = new IdentityZone();
        testZone.getConfig().setClientSecretPolicy(new ClientSecretPolicy(0,255,0,0,0,0,6));
        IdentityZoneHolder.set(testZone);
    }

    @AfterAll
    static void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Nested
    class WhenClientSecretHasExpired {
        @Test
        void continuesWithFilterChain() throws IOException, ServletException {
            BaseClientDetails clientDetails = new BaseClientDetails("client-1", "none", "uaa.none", "client_credentials", "http://localhost:5000/uaadb" );


            Calendar expiredDate = Calendar.getInstance();
            expiredDate.set(2016, 1, 1);
            clientDetails.setAdditionalInformation(createTestAdditionalInformation(expiredDate));

            when(clientDetailsService.loadClientByClientId(Mockito.matches("app"))).thenReturn(clientDetails);

            MockFilterChain chain = mock(MockFilterChain.class);
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.addHeader("Authorization", "Basic " + CREDENTIALS_HEADER_STRING);
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            verify(clientAuthenticationManager).authenticate(any(Authentication.class));
        }
    }

    @Nested
    class WhenClientSecretHasNotExpired {
        @Test
        void continuesWithFilterChain() throws IOException, ServletException {
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
    }

    private Map<String, Object> createTestAdditionalInformation(Calendar calendar) {
        Map<String,Object> additionalInformation = new HashMap<>();
        additionalInformation.put(ClientConstants.LAST_MODIFIED, new Timestamp(calendar.getTimeInMillis()));

        return additionalInformation;
    }
}