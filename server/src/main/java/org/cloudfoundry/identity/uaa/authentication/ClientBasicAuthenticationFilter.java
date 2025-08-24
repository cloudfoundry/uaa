package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


/**
 * A filter which implements basic auth according to the requirements laid out in RFC6749.
 * https://tools.ietf.org/html/rfc6749#section-2.3.1
 *
 * This filter properly decodes a basic auth header of the form:
 * Authentication: Basic base64encode(urlencode(client_id):urlencode(client_secret))
 *
 * Fun fact: this class is almost an exact copy of the Spring Framework {@link BasicAuthenticationFilter} version 5.1.5.RELEASE.
 */
public class ClientBasicAuthenticationFilter extends OncePerRequestFilter {
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final AuthenticationManager authenticationManager;
    private final boolean enableUriEncodingCompatibilityMode;

    /**
     * Creates an instance which will authenticate against the supplied
     * {@code AuthenticationManager} and use the supplied {@code AuthenticationEntryPoint}
     * to handle authentication failures.
     *
     * @param authenticationManager the bean to submit authentication requests to
     * @param authenticationEntryPoint will be invoked when authentication fails.
     * Typically an instance of {@link BasicAuthenticationEntryPoint}.
     */
    public ClientBasicAuthenticationFilter(AuthenticationManager authenticationManager,
            AuthenticationEntryPoint authenticationEntryPoint,
            boolean enableUriEncodingCompatibilityMode) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(authenticationEntryPoint,
                "authenticationEntryPoint cannot be null");
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.enableUriEncodingCompatibilityMode = enableUriEncodingCompatibilityMode;
    }

    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource,
                "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
        Assert.notNull(this.authenticationEntryPoint, "An AuthenticationEntryPoint is required");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        final boolean debug = this.logger.isDebugEnabled();

        String header = request.getHeader("Authorization");

        if (header == null || !header.toLowerCase().startsWith("basic ")) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String[] tokens = extractAndDecodeHeader(header, request);
            assert tokens.length == 2;

            String clientId;
            String clientSecret;
            String headerEncodedCreds = request.getHeader("X-CF-ENCODED-CREDENTIALS");
            if (headerEncodedCreds == null) {
                headerEncodedCreds = "false";
            }

            if (enableUriEncodingCompatibilityMode && !"true".equals(headerEncodedCreds.toLowerCase())) {
                clientId = tokens[0];
                clientSecret = tokens[1];
            } else {
                try {
                    clientId = URLDecoder.decode(tokens[0], getCredentialsCharset(request));
                    clientSecret = URLDecoder.decode(tokens[1], getCredentialsCharset(request));
                } catch (UnsupportedEncodingException | IllegalArgumentException e) {
                    throw new BadCredentialsException("Failed to URL Decode credentials");
                }
            }

            request.setAttribute("clientId", clientId);
            if (debug) {
                this.logger
                        .debug("Basic Authentication Authorization header found for user '"
                                + clientId + "'");
            }

            UsernamePasswordAuthenticationToken authRequest =
                    new UsernamePasswordAuthenticationToken(clientId, clientSecret);
            authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
            Authentication authResult = this.authenticationManager.authenticate(authRequest);

            if (debug) {
                this.logger.debug("Authentication success: " + authResult);
            }

            SecurityContextHolder.getContext().setAuthentication(authResult);
        }
        catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();

            if (debug) {
                this.logger.debug("Authentication request for failed: " + failed);
            }

            this.authenticationEntryPoint.commence(request, response, failed);
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * Decodes the header into a username and password.
     *
     * @throws BadCredentialsException if the Basic header is not present or is not valid
     * Base64
     */
    private String[] extractAndDecodeHeader(String header, HttpServletRequest request)
            throws IOException {

        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Token);
        }
        catch (IllegalArgumentException e) {
            throw new BadCredentialsException(
                    "Failed to decode basic authentication token");
        }

        String token = new String(decoded, getCredentialsCharset(request));

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[]{token.substring(0, delim), token.substring(delim + 1)};
    }

    private String getCredentialsCharset(HttpServletRequest httpRequest) {
        return "UTF-8";
    }
}
