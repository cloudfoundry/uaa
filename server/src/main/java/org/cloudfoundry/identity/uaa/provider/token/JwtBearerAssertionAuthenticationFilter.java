package org.cloudfoundry.identity.uaa.provider.token;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;
import org.cloudfoundry.identity.uaa.provider.KeyProviderProvisioning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;

public class JwtBearerAssertionAuthenticationFilter extends OncePerRequestFilter {
    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final Logger logger = LoggerFactory.getLogger(JwtBearerAssertionAuthenticationFilter.class);

    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider publicKeyProvider;
    private KeyProviderProvisioning keyProviderProvisioning;
    private AuthenticationEntryPoint oauthAuthenticationEntryPoint;
    private String proxyPublicKey;
    private TokenGranter dcsEndpointTokenGranter;

    @Value("${ENFORCE_CLIENT_ASSERTION_HEADER:true}")
    private boolean enforceClientAssertionHeader;

    @Value("${CLIENT_ASSERTION_TTL:15}")
    private Integer clientAssertionHeaderTTL;
    
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
        	if(grantType == null){
        		throw new MissingGrantTypeException("Missing grant type.");
        	}
        	else if (grantType.equals(GRANT_TYPE_JWT_BEARER)) {
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

    public void setKeyProviderProvisioning(final KeyProviderProvisioning keyProviderProvisioning) {
        this.keyProviderProvisioning = keyProviderProvisioning;
    }

    public void setDcsEndpointTokenGranter(final TokenGranter dcsEndpointTokenGranter) {
        this.dcsEndpointTokenGranter = dcsEndpointTokenGranter;
    }

    private Authentication authenticateJwtAssertion(final HttpServletRequest request, String jwtAssertion) {
        JwtBearerAssertionTokenAuthenticator tokenAuthenticator = new JwtBearerAssertionTokenAuthenticator(
                request.getRequestURL().toString(), this.clientAssertionHeaderTTL);
        tokenAuthenticator.setClientDetailsService(this.clientDetailsService);
        tokenAuthenticator.setClientPublicKeyProvider(this.publicKeyProvider);
        tokenAuthenticator.setDcsEndpointTokenGranter(this.dcsEndpointTokenGranter);
        tokenAuthenticator.setKeyProviderProvisioning(this.keyProviderProvisioning);

        if (this.enforceClientAssertionHeader) {
            return tokenAuthenticator.authenticate(jwtAssertion,
                    request.getHeader(PREDIX_CLIENT_ASSERTION_HEADER), this.proxyPublicKey);
        } else {
            return tokenAuthenticator.authenticateWithoutClientAssertionHeader(jwtAssertion);
        }
    }
}

@SuppressWarnings("serial")
class MissingGrantTypeException extends AuthenticationException {

    public MissingGrantTypeException(String msg) {
        super(msg);
    }

    public MissingGrantTypeException(String msg, Throwable t) {
        super(msg, t);
    }
}
