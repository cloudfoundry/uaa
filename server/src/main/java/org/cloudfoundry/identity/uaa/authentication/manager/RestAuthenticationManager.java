/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * An authentication manager that can be used to login to a remote UAA service
 * with username and password credentials,
 * without the local server needing to know anything about the user accounts.
 * The request is handled by the UAA's
 * RemoteAuhenticationEndpoint and success or failure is determined by the
 * response code.
 *
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
public class RestAuthenticationManager implements AuthenticationManager {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private RestOperations restTemplate = new RestTemplate();

    private static final String DEFAULT_LOGIN_URL = "http://uaa.cloudfoundry.com/authenticate";

    private String remoteUrl = DEFAULT_LOGIN_URL;

    private boolean nullPassword;


    /**
     * @param remoteUrl the login url to set
     */
    public void setRemoteUrl(String remoteUrl) {
        this.remoteUrl = remoteUrl;
    }

    public String getRemoteUrl() {
        return remoteUrl;
    }

    /**
     * @param restTemplate a rest template to use
     */
    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public RestOperations getRestTemplate() {
        return restTemplate;
    }

    public RestAuthenticationManager() {
        RestTemplate restTemplate = new RestTemplate();
        // The default java.net client doesn't allow you to handle 4xx responses
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse statusCode) throws IOException {
                return HttpStatus.resolve(statusCode.getStatusCode().value()).is5xxServerError();

            }
        });
        this.restTemplate = restTemplate;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();

        HttpHeaders headers = getHeaders();

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = restTemplate.exchange(remoteUrl, HttpMethod.POST,
                new HttpEntity<Object>(getParameters(username, (String) authentication.getCredentials()), headers), Map.class);

        if (response.getStatusCode() == HttpStatus.OK || response.getStatusCode() == HttpStatus.CREATED) {
            if (evaluateResponse(authentication, response)) {
                logger.info("Successful authentication request for {}", authentication.getName());
                return new UsernamePasswordAuthenticationToken(username, nullPassword ? null : "", UaaAuthority.USER_AUTHORITIES);
            }
        } else if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            logger.info("Failed authentication request");
            throw new BadCredentialsException("Authentication failed");
        } else if (response.getStatusCode() == HttpStatus.INTERNAL_SERVER_ERROR) {
            logger.info("Internal error from UAA. Please Check the UAA logs.");
        } else {
            logger.error("Unexpected status code {} from the UAA." +
                    " Is a compatible version running?", response.getStatusCode());
        }
        throw new RuntimeException("Could not authenticate with remote server");
    }

    protected boolean evaluateResponse(Authentication authentication, ResponseEntity<Map> response) {
        String userFromUaa = Optional.ofNullable(response.getBody()).map(b -> b.get("username")).filter(String.class::isInstance).map(String.class::cast).orElse(null);
        return Optional.ofNullable(userFromUaa).stream().anyMatch(u -> u.equals(authentication.getPrincipal().toString()));
    }

    protected Object getParameters(String username, String password) {
        MultiValueMap<String, Object> parameters = new LinkedMaskingMultiValueMap<>("password");
        parameters.set("username", username);
        parameters.set("password", password);
        return parameters;
    }

    protected HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    public boolean isNullPassword() {
        return nullPassword;
    }

    public void setNullPassword(boolean nullPassword) {
        this.nullPassword = nullPassword;
    }
}
