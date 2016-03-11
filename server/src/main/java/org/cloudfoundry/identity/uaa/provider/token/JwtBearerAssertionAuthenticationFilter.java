package org.cloudfoundry.identity.uaa.provider.token;

import java.io.IOException;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.BackwardsCompatibleTokenEndpointAuthenticationFilter;
import org.cloudfoundry.identity.uaa.oauth.OauthGrant;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ge.predix.pki.device.spi.DevicePublicKeyProvider;

public class JwtBearerAssertionAuthenticationFilter extends OncePerRequestFilter {
    private static final Log logger = LogFactory.getLog(BackwardsCompatibleTokenEndpointAuthenticationFilter.class);

    private ClientDetailsService clientDetailsService;
    private DevicePublicKeyProvider publicKeyProvider;
    private AuthenticationEntryPoint oauthAuthenticationEntryPoint;
    
    /**
     * An authentication entry point that can handle unsuccessful authentication. Defaults to an
     * {@link OAuth2AuthenticationEntryPoint}.
     *
     * @param authenticationEntryPoint the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.oauthAuthenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        final boolean debug = logger.isDebugEnabled();
        String grantType = request.getParameter(OAuth2Utils.GRANT_TYPE);
        
        try {

            if (grantType.equals(OauthGrant.JWT_BEARER)) {
                String assertion = request.getParameter("assertion");
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (!StringUtils.isEmpty(assertion)) {
                    //This throws AuthenticationException if authentication fails.
                    authentication = performClientAuthentication(request, assertion);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
                else {
                    throw new BadCredentialsException("No assertion token provided.");
                }
            }
            
        } catch (BadCredentialsException e) {
            //happens when all went well, but the device/machine failed Authentication...
            SecurityContextHolder.clearContext();
            if (debug) {
                logger.debug("jwt-bearer authentication failed." + e);
            }
            oauthAuthenticationEntryPoint.commence(request, response, e);
            return;
        } 
        
        filterChain.doFilter(request, response);
    }
    

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setPublicKeyProvider(DevicePublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
    }

    private Authentication performClientAuthentication(HttpServletRequest request, String assertion) {
        JwtBearerAssertionTokenAuthenticator tokenAuthenticator = 
                new JwtBearerAssertionTokenAuthenticator(request.getRequestURL().toString());
        tokenAuthenticator.setClientDetailsService(clientDetailsService);
        tokenAuthenticator.setClientPublicKeyProvider(this.publicKeyProvider);
        return tokenAuthenticator.authenticate(assertion);
    }

}
