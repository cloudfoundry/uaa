/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.login;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.BackwardsCompatibleTokenEndpointAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;

/**
 * Authentication filter to verify one time passwords with what's cached in the
 * one time password store.
 *
 *
 */
public class PasscodeAuthenticationFilter extends BackwardsCompatibleTokenEndpointAuthenticationFilter {

    private final Log logger = LogFactory.getLog(getClass());

    private List<String> parameterNames = Collections.emptyList();

    public PasscodeAuthenticationFilter(UaaUserDatabase uaaUserDatabase, AuthenticationManager authenticationManager, OAuth2RequestFactory oAuth2RequestFactory, ExpiringCodeStore expiringCodeStore) {
        super(
            new ExpiringCodeAuthenticationManager(
                uaaUserDatabase,
                authenticationManager,
                LogFactory.getLog(PasscodeAuthenticationFilter.class),
                expiringCodeStore,
                Collections.singleton(HttpMethod.POST.toString())),
            oAuth2RequestFactory);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        PasscodeHttpServletRequest request = new PasscodeHttpServletRequest((HttpServletRequest)req);
        super.doFilter(request, res, chain);
    }

    protected static class ExpiringCodeAuthentication implements Authentication {
        private final HttpServletRequest request;
        private final String passcode;

        public ExpiringCodeAuthentication(HttpServletRequest request, String passcode) {
            this.request = request;
            this.passcode = passcode;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public boolean isAuthenticated() {
            return false;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        }

        public HttpServletRequest getRequest() {
            return request;
        }

        public String getPasscode() {
            return passcode;
        }

        @Override
        public String getName() {
            return getPasscode();
        }
    }

    protected static class PasscodeHttpServletRequest extends HttpServletRequestWrapper {

        Map<String, String[]> extendedParameters = new HashMap<>();

        public PasscodeHttpServletRequest(HttpServletRequest request) {
            super(request);
        }

        public void addParameter(String name, String[] values) {
            extendedParameters.put(name, values);
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> result = new HashMap<>(extendedParameters);
            result.putAll(super.getParameterMap());
            return result;
        }
    }

    protected static class ExpiringCodeAuthenticationManager implements AuthenticationManager {
        private final Log logger;
        private final ExpiringCodeStore expiringCodeStore;
        private final Set<String> methods;
        private final AuthenticationManager parent;
        private final UaaUserDatabase uaaUserDatabase;

        public ExpiringCodeAuthenticationManager(UaaUserDatabase uaaUserDatabase, AuthenticationManager parent, Log logger, ExpiringCodeStore expiringCodeStore, Set<String> methods) {
            this.logger = logger;
            this.expiringCodeStore = expiringCodeStore;
            this.methods = methods;
            this.parent = parent;
            this.uaaUserDatabase = uaaUserDatabase;
        }

        protected ExpiringCode doRetrieveCode(String code) {
            return expiringCodeStore.retrieveCode(code);
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if (!(authentication instanceof PasscodeAuthenticationFilter.ExpiringCodeAuthentication)) {
                return parent.authenticate(authentication);
            } else {
                PasscodeAuthenticationFilter.ExpiringCodeAuthentication expiringCodeAuthentication = (PasscodeAuthenticationFilter.ExpiringCodeAuthentication) authentication;
                // Validate passcode
                logger.debug("Located credentials in request, with passcode");
                if (methods != null && !methods.contains(expiringCodeAuthentication.getRequest().getMethod().toUpperCase())) {
                    throw new BadCredentialsException("Credentials must be sent by (one of methods): " + methods);
                }

                ExpiringCode eCode = doRetrieveCode(expiringCodeAuthentication.getPasscode());
                PasscodeInformation pi = null;
                if (eCode != null && eCode.getData() != null) {
                    try {
                        pi = JsonUtils.readValue(eCode.getData(), PasscodeInformation.class);
                    } catch (JsonUtils.JsonUtilException e) {
                        throw new InsufficientAuthenticationException("Unable to deserialize passcode object.", e);
                    }
                }

                if (pi == null) {
                    throw new InsufficientAuthenticationException("Passcode information is missing.");
                }
                logger.debug("Successful passcode authentication request for " + pi.getUsername());

                Collection<GrantedAuthority> externalAuthorities = null;

                if (null != pi.getAuthorizationParameters()) {
                    externalAuthorities = (Collection<GrantedAuthority>) pi.getAuthorizationParameters().get("authorities");
                }
                UaaPrincipal principal = new UaaPrincipal(pi.getUserId(), pi.getUsername(), null, pi.getOrigin(), null,
                    IdentityZoneHolder.get().getId());
                List<? extends GrantedAuthority> authorities;
                try {
                    UaaUser user = uaaUserDatabase.retrieveUserById(pi.getUserId());
                    authorities = user.getAuthorities();
                } catch (UsernameNotFoundException x) {
                    throw new BadCredentialsException("Invalid user.");
                }
                Authentication result = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    externalAuthorities == null || externalAuthorities.size() == 0 ? authorities : externalAuthorities
                );

                //add additional parameters for backwards compatibility
                PasscodeHttpServletRequest pcRequest = (PasscodeHttpServletRequest)expiringCodeAuthentication.getRequest();
                //pcRequest.addParameter("user_id", new String[] {pi.getUserId()});
                pcRequest.addParameter("username", new String[] {pi.getUsername()});
                pcRequest.addParameter(Origin.ORIGIN, new String[] {pi.getOrigin()});

                return result;
            }

        }
    }

    @Override
    protected Authentication extractCredentials(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (grantType != null && grantType.equals("password")) {
            Map<String, String> credentials = getCredentials(request);
            String passcode = credentials.get("passcode");
            if (passcode!=null) {
                return new ExpiringCodeAuthentication(request, passcode);
            } else {
                return super.extractCredentials(request);
            }
        }
        return null;
    }
    private Map<String, String> getCredentials(HttpServletRequest request) {
        Map<String, String> credentials = new HashMap<String, String>();

        for (String paramName : parameterNames) {
            String value = request.getParameter(paramName);
            if (value != null) {
                if (value.startsWith("{")) {
                    try {
                        Map<String, String> jsonCredentials = JsonUtils.readValue(value,
                                        new TypeReference<Map<String, String>>() {
                                        });
                        credentials.putAll(jsonCredentials);
                    } catch (JsonUtils.JsonUtilException e) {
                        logger.warn("Unknown format of value for request param: " + paramName + ". Ignoring.");
                    }
                }
                else {
                    credentials.put(paramName, value);
                }
            }
        }

        return credentials;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }

    public void setParameterNames(List<String> parameterNames) {
        this.parameterNames = parameterNames;
    }
}