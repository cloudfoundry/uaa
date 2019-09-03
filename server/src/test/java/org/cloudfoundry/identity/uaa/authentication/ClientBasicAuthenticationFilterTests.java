package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Base64;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ClientBasicAuthenticationFilterTests {
    private ClientBasicAuthenticationFilter filter;
    private AuthenticationManager clientAuthenticationManager;
    private AuthenticationDetailsSource<HttpServletRequest, ?> uaaAuthenticationDetailsSource;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        IdentityZone testZone = new IdentityZone();
        IdentityZoneHolder.set(testZone);

        clientAuthenticationManager = mock(AuthenticationManager.class);
        uaaAuthenticationDetailsSource = mock(UaaAuthenticationDetailsSource.class);

        filter = new ClientBasicAuthenticationFilter(clientAuthenticationManager, mock(AuthenticationEntryPoint.class));
        filter.setAuthenticationDetailsSource(uaaAuthenticationDetailsSource);
    }

    @AfterAll
    static void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Nested
    class ByDefault {
        private void addBasicAuthHeader(MockHttpServletRequest request, String clientId, String clientSecret) throws UnsupportedEncodingException {
            String encodedClientId = URLEncoder.encode(clientId, "UTF-8");
            String encodedClientSecret = URLEncoder.encode(clientSecret, "UTF-8");
            String encodedCredentials = new String(
                Base64.getEncoder().encode((encodedClientId + ":" + encodedClientSecret).getBytes())
            );

            request.addHeader("Authorization", "Basic " + encodedCredentials);
        }

        @Test
        void urlDecodesClientIdAndClientSecret() throws IOException, ServletException {
            String clientId = "app|whatever";
            String clientSecret = "sec|ret";
            MockFilterChain chain = mock(MockFilterChain.class);
            MockHttpServletRequest request = new MockHttpServletRequest();
            MockHttpServletResponse response = new MockHttpServletResponse();
            addBasicAuthHeader(request, clientId, clientSecret);

            filter.doFilter(request, response, chain);

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
            token.setDetails(uaaAuthenticationDetailsSource.buildDetails(request));
            verify(clientAuthenticationManager).authenticate(token);
        }
    }
}