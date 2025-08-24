package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Optional.ofNullable;

/**
 * Filter which processes authentication submitted through the
 * <code>/authorize</code> endpoint.
 * <p>
 * Checks the submitted information for a parameter named "credentials" (or
 * specified via the {@link #setParameterNames(List) parameter name}), in JSON
 * format.
 * <p>
 * If the parameter is found, it will submit an authentication request to the
 * AuthenticationManager and attempt to authenticate the user. If authentication
 * fails, it will return an error message. Otherwise, it creates a security
 * context and allows the request to continue.
 * <p>
 * If the parameter is not present, the filter will have no effect.
 * <p>
 * See <a
 * href="https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.md">UUA
 * API Docs</a>
 */
public class AuthzAuthenticationFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final AuthenticationManager authenticationManager;

    private List<String> parameterNames = Collections.emptyList();

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private Set<String> methods = Collections.singleton(HttpMethod.POST.toString());

    private AccountSavingAuthenticationSuccessHandler successHandler;

    /**
     * The filter fails on requests that don't have one of these HTTP methods.
     *
     * @param methods the methods to set (defaults to POST)
     */
    public void setMethods(Set<String> methods) {
        this.methods = new HashSet<>();
        for (String method : methods) {
            this.methods.add(method.toUpperCase());
        }
    }

    /**
     * @param authenticationEntryPoint the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public void setSuccessHandler(AccountSavingAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    /**
     * The name of the parameter to extract credentials from. Request parameters
     * with these names are extracted and
     * passed as credentials to the authentication manager. A request that
     * doesn't have any of the specified parameters
     * is ignored.
     *
     * @param parameterNames the parameter names to set (default empty)
     */
    public void setParameterNames(List<String> parameterNames) {
        this.parameterNames = parameterNames;
    }

    public AuthzAuthenticationFilter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "[Assertion failed] - authenticationManager is required; it must not be null");
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        Map<String, String> loginInfo = UaaHttpRequestUtils.getCredentials(req, parameterNames);

        boolean buggyVmcAcceptHeader = false;

        try {
            if (loginInfo.isEmpty()) {
                throw new BadCredentialsException("Request does not contain credentials.");
            } else {
                logger.debug("Located credentials in request, with keys: {}", UaaStringUtils.getCleanedUserControlString(loginInfo.keySet().toString()));
                if (methods != null && !methods.contains(req.getMethod().toUpperCase())) {
                    throw new BadCredentialsException("Credentials must be sent by (one of methods): " + methods);
                }
                Authentication result = authenticationManager.authenticate(new AuthzAuthenticationRequest(loginInfo,
                        new UaaAuthenticationDetails(req)));

                if (result.isAuthenticated()) {
                    SecurityContextHolder.getContext().setAuthentication(result);
                    ofNullable(successHandler).ifPresent(s -> s.setSavedAccountOptionCookie(req, res, result));

                    UaaAuthentication uaaAuthentication = (UaaAuthentication) result;
                    if (SessionUtils.isPasswordChangeRequired(req.getSession())) {
                        throw new PasswordChangeRequiredException(uaaAuthentication, "password change required");
                    }
                }
            }
        } catch (AuthenticationException e) {
            logger.debug("Authentication failed");

            String acceptHeaderValue = req.getHeader("accept");
            String clientId = req.getParameter("client_id");
            if ("*/*; q=0.5, application/xml".equals(acceptHeaderValue) && "vmc".equals(clientId)) {
                buggyVmcAcceptHeader = true;
            }

            if (buggyVmcAcceptHeader) {
                HttpServletRequest jsonAcceptingRequest = new HttpServletRequestWrapper(req) {

                    @Override
                    public Enumeration<String> getHeaders(String name) {
                        if ("accept".equalsIgnoreCase(name)) {
                            return new JsonInjectedEnumeration(((HttpServletRequest) getRequest()).getHeaders(name));
                        } else {
                            return ((HttpServletRequest) getRequest()).getHeaders(name);
                        }
                    }

                    @Override
                    public String getHeader(String name) {
                        if ("accept".equalsIgnoreCase(name)) {
                            return "application/json";
                        } else {
                            return ((HttpServletRequest) getRequest()).getHeader(name);
                        }
                    }
                };

                authenticationEntryPoint.commence(jsonAcceptingRequest, res, e);
            } else {
                authenticationEntryPoint.commence(req, res, e);
            }
            return;
        }

        chain.doFilter(request, response);
    }


    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    static class JsonInjectedEnumeration implements Enumeration<String> {
        private Enumeration<String> underlying;

        public JsonInjectedEnumeration(Enumeration<String> underlying) {
            this.underlying = underlying;
        }

        @Override
        public boolean hasMoreElements() {
            return underlying.hasMoreElements();
        }

        @Override
        public String nextElement() {
            underlying.nextElement();
            return "application/json";
        }

    }
}