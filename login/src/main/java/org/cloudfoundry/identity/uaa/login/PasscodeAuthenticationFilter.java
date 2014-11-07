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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.client.RestTemplate;

/**
 * Authentication filter to verify one time passwords with what's cached in the
 * one time password store.
 * 
 * @author jdsa
 * 
 */
public class PasscodeAuthenticationFilter implements Filter {

    private final Log logger = LogFactory.getLog(getClass());

    private List<String> parameterNames = Collections.emptyList();

    private final Set<String> methods = Collections.singleton(HttpMethod.POST.toString());

    private final AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    private final ObjectMapper mapper = new ObjectMapper();

    private AuthenticationManager authenticationManager;

    private RestTemplate authorizationTemplate;

    private String uaaBaseUrl;

    public String getUaaBaseUrl() {
        return uaaBaseUrl;
    }

    public void setUaaBaseUrl(String uaaBaseUrl) {
        this.uaaBaseUrl = uaaBaseUrl;
    }

    public RestTemplate getAuthorizationTemplate() {
        return authorizationTemplate;
    }

    public void setAuthorizationTemplate(RestTemplate authorizationTemplate) {
        this.authorizationTemplate = authorizationTemplate;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
                    ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        Map<String, String> loginInfo = getCredentials(req);

        String username = loginInfo.get("username");
        String password = loginInfo.get("password");
        String passcode = loginInfo.get("passcode");

        if (loginInfo.isEmpty()) {
            throw new BadCredentialsException("Request does not contain credentials.");
        } else if (null == password && null != passcode) {
            // Validate passcode
            logger.debug("Located credentials in request, with keys: " + loginInfo.keySet());
            if (methods != null && !methods.contains(req.getMethod().toUpperCase())) {
                throw new BadCredentialsException("Credentials must be sent by (one of methods): " + methods);
            }

            ExpiringCode eCode = doRetrieveCode(passcode);
            PasscodeInformation pi = null;
            if (eCode != null && eCode.getData() != null) {
                pi = new ObjectMapper().readValue(eCode.getData(), PasscodeInformation.class);
            }

            if (pi != null) {
                logger.info("Successful authentication request for " + username);

                Collection<GrantedAuthority> externalAuthorities = null;

                if (null != pi.getAuthorizationParameters()) {
                    externalAuthorities = (Collection<GrantedAuthority>) pi.getAuthorizationParameters().get(
                                    "authorities");
                }
                SocialClientUserDetails principal = new SocialClientUserDetails(pi.getUsername(), pi.getSamlAuthorities());
                principal.setSource(pi.getOrigin());
                Authentication result = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    externalAuthorities == null ? UaaAuthority.USER_AUTHORITIES : externalAuthorities
                );

                SecurityContextHolder.getContext().setAuthentication(result);
            } else {
                authenticationEntryPoint.commence(req, res, new BadCredentialsException("Invalid passcode"));
            }
        } else {
            // Authenticate user against the UAA
            logger.debug("Located credentials in request, with keys: " + loginInfo.keySet());
            if (methods != null && !methods.contains(req.getMethod().toUpperCase())) {
                throw new BadCredentialsException("Credentials must be sent by (one of methods): " + methods);
            }
            Authentication result = authenticationManager.authenticate(new AuthzAuthenticationRequest(loginInfo,
                            new UaaAuthenticationDetails(req)));
            SecurityContextHolder.getContext().setAuthentication(result);
        }

        chain.doFilter(request, response);
    }

    public ExpiringCode doRetrieveCode(String code) {
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.add("Accept", MediaType.APPLICATION_JSON_VALUE);

        HttpEntity<ExpiringCode> requestEntity = new HttpEntity<ExpiringCode>(null, requestHeaders);

        ResponseEntity<ExpiringCode> response = authorizationTemplate.exchange(getUaaBaseUrl() + "/Codes/" + code,
                        HttpMethod.GET,
                        requestEntity, ExpiringCode.class);

        if (response.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
            return null;
        } else if (response.getStatusCode() != HttpStatus.OK) {
            logger.warn("Request failed: " + requestEntity);
            // TODO throw exception with the correct error
            throw new BadCredentialsException("Unable to retrieve passcode:" + String.valueOf(response.getStatusCode()));
        }

        return response.getBody();
    }

    private Map<String, String> getCredentials(HttpServletRequest request) {
        Map<String, String> credentials = new HashMap<String, String>();

        for (String paramName : parameterNames) {
            String value = request.getParameter(paramName);
            if (value != null) {
                if (value.startsWith("{")) {
                    try {
                        Map<String, String> jsonCredentials = mapper.readValue(value,
                                        new TypeReference<Map<String, String>>() {
                                        });
                        credentials.putAll(jsonCredentials);
                    } catch (IOException e) {
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

    public PasscodeAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

}