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

import java.io.IOException;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.codehaus.jackson.map.ObjectMapper;
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
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 * 
 */
public class AutologinAuthenticationManager implements AuthenticationManager {

    private Log logger = LogFactory.getLog(getClass());

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
            throw new RuntimeException(String.valueOf(response.getStatusCode()));
        }

        return response.getBody();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!(authentication instanceof AuthzAuthenticationRequest)) {
            return null;
        }

        AuthzAuthenticationRequest request = (AuthzAuthenticationRequest) authentication;
        Map<String, String> info = request.getInfo();
        String code = info.get("code");

        ExpiringCode ec = doRetrieveCode(code);
        SocialClientUserDetails user = null;
        try {
            if (ec != null) {
                user = new ObjectMapper().readValue(ec.getData(), SocialClientUserDetails.class);
            }
        } catch (IOException x) {
            throw new BadCredentialsException("JsonConversion error", x);
        }

        if (user == null) {
            throw new BadCredentialsException("Cannot redeem provided code for user");
        }

        // ensure that we stored clientId
        String clientId = null;
        String origin = null;
        String userId = null;
        Object principal = user.getUsername();
        if (user.getDetails() instanceof String) {
            clientId = (String) user.getDetails();
        } else if (user.getDetails() instanceof Map) {
            Map<String,String> map = (Map<String,String>)user.getDetails();
            clientId = map.get("client_id");
            origin = map.get(Origin.ORIGIN);
            userId = map.get("user_id");
            principal = new UaaPrincipal(userId,user.getUsername(),null,origin,null);
        }
        if (clientId == null) {
            throw new BadCredentialsException("Cannot redeem provided code for user, client id missing");
        }

        // validate the client Id
        if (!(authentication.getDetails() instanceof UaaAuthenticationDetails)) {
            throw new BadCredentialsException("Cannot redeem provided code for user, auth details missing");
        }

        UaaAuthenticationDetails details = (UaaAuthenticationDetails) authentication.getDetails();
        if (!clientId.equals(details.getClientId())) {
            throw new BadCredentialsException("Cannot redeem provided code for user, client mismatch");
        }

        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(principal, null, user.getAuthorities());
        result.setDetails(authentication.getDetails());
        return result;

    }

}
