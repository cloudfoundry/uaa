package org.cloudfoundry.identity.uaa.provider.token;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.OauthGrant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;

public class JwtBearerAssertionAuthenticationFilter extends OncePerRequestFilter {
    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final Log logger = LogFactory.getLog(JwtBearerAssertionAuthenticationFilter.class);

    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider publicKeyProvider;
    private AuthenticationEntryPoint oauthAuthenticationEntryPoint;
    private String proxyPublicKey;

    @Value("${ENFORCE_CLIENT_ASSERTION_HEADER:true}")
    private boolean enforceClientAssertionHeader;

    /**
     * An authentication entry point that can handle unsuccessful authentication. Defaults to an
     * {@link OAuth2AuthenticationEntryPoint}.
     *
     * @param authenticationEntryPoint
     *            the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
        this.oauthAuthenticationEntryPoint = authenticationEntryPoint;
    }

    public void setProxyPublicKey(final String proxyPublicKey) {
        this.proxyPublicKey = proxyPublicKey;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain filterChain) throws ServletException, IOException {
        String grantType = request.getParameter(OAuth2Utils.GRANT_TYPE);

        try {
            if (grantType.equals(OauthGrant.JWT_BEARER)) {
                String assertion = request.getParameter("assertion");
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                if (StringUtils.isEmpty(assertion)) {
                    throw new BadCredentialsException("No assertion token provided.");
                }

                authentication = authenticateJwtAssertion(request, assertion);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (AuthenticationException e) {
            SecurityContextHolder.clearContext();
            logger.debug("jwt-bearer authentication failed. " + e.getMessage());
            this.oauthAuthenticationEntryPoint.commence(request, response, e);
            return;
        }

        filterChain.doFilter(request, response);
    }

    public void setClientDetailsService(final ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setPublicKeyProvider(final DevicePublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
    }

    private Authentication authenticateJwtAssertion(final HttpServletRequest request, String jwtAssertion) {
        JwtBearerAssertionTokenAuthenticator tokenAuthenticator = new JwtBearerAssertionTokenAuthenticator(
                request.getRequestURL().toString());
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.setClientPublicKeyProvider(this.publicKeyProvider);

        if (this.enforceClientAssertionHeader) {
            return tokenAuthenticator.authenticate(jwtAssertion,
                    request.getHeader(PREDIX_CLIENT_ASSERTION_HEADER), this.proxyPublicKey);
        } else {
            return tokenAuthenticator.authenticate(jwtAssertion);
        }
    }
}
