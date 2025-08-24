package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class TokenEndpointAuthenticationFilter implements Filter {

    private static final Log logger = LogFactory.getLog(TokenEndpointAuthenticationFilter.class);

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private final AuthenticationManager authenticationManager;

    private final OAuth2RequestFactory oAuth2RequestFactory;

    /**
     * @param authenticationManager an AuthenticationManager for the incoming request
     */
    public TokenEndpointAuthenticationFilter(AuthenticationManager authenticationManager, OAuth2RequestFactory oAuth2RequestFactory) {
        super();
        this.authenticationManager = authenticationManager;
        this.oAuth2RequestFactory = oAuth2RequestFactory;
    }

    /**
     * An authentication entry point that can handle unsuccessful authentication. Defaults to an
     * {@link OAuth2AuthenticationEntryPoint}.
     * 
     * @param authenticationEntryPoint the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    /**
     * A source of authentication details for requests that result in authentication.
     * 
     * @param authenticationDetailsSource the authenticationDetailsSource to set
     */
    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
            ServletException {

        final boolean debug = logger.isDebugEnabled();
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        try {
            Authentication credentials = extractCredentials(request);

            if (credentials != null) {

                if (debug) {
                    logger.debug("Authentication credentials found");
                }

                Authentication authResult = authenticationManager.authenticate(credentials);

                if (debug) {
                    logger.debug("Authentication success: " + authResult.getName());
                }

                Authentication clientAuth = SecurityContextHolder.getContext().getAuthentication();
                if (clientAuth == null) {
                    throw new BadCredentialsException(
                            "No client authentication found. Remember to put a filter upstream of the TokenEndpointAuthenticationFilter.");
                }

                Map<String, String> map = getSingleValueMap(request);
                map.put(OAuth2Utils.CLIENT_ID, clientAuth.getName());
                AuthorizationRequest authorizationRequest = oAuth2RequestFactory.createAuthorizationRequest(map);

                authorizationRequest.setScope(getScope(request));
                if (clientAuth.isAuthenticated()) {
                    // Ensure the OAuth2Authentication is authenticated
                    authorizationRequest.setApproved(true);
                }

                OAuth2Request storedOAuth2Request = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);

                SecurityContextHolder.getContext().setAuthentication(
                        new OAuth2Authentication(storedOAuth2Request, authResult));

                onSuccessfulAuthentication(request, response, authResult);

            }

        }
        catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();

            if (debug) {
                logger.debug("Authentication request for failed: " + failed);
            }

            onUnsuccessfulAuthentication(request, response, failed);

            authenticationEntryPoint.commence(request, response, failed);

            return;
        }

        chain.doFilter(request, response);
    }

    private Map<String, String> getSingleValueMap(HttpServletRequest request) {
        Map<String, String> map = new HashMap<>();
        Map<String, String[]> parameters = request.getParameterMap();
        for (Iterator<String> iterator = parameters.keySet().iterator(); iterator.hasNext(); ) {
            String key = iterator.next();
            String[] values = parameters.get(key);
            map.put(key, values != null && values.length > 0 ? values[0] : null);
        }
        return map;
    }

    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) throws IOException {
        // empty
    }

    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException {
        // empty
    }

    /**
     * If the incoming request contains user credentials in headers or parameters then extract them here into an
     * Authentication token that can be validated later. This implementation only recognises password grant requests and
     * extracts the username and password.
     * 
     * @param request the incoming request, possibly with user credentials
     * @return an authentication for validation (or null if there is no further authentication)
     */
    protected Authentication extractCredentials(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2Utils.GRANT_TYPE);
        if ("password".equals(grantType)) {
            UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                    request.getParameter("username"), request.getParameter("password"));
            result.setDetails(authenticationDetailsSource.buildDetails(request));
            return result;
        }
        return null;
    }

    private Set<String> getScope(HttpServletRequest request) {
        return OAuth2Utils.parseParameterList(request.getParameter(OAuth2Utils.SCOPE));
    }

}
