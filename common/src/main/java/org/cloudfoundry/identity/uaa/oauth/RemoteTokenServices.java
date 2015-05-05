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
package org.cloudfoundry.identity.uaa.oauth;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Queries the /check_token endpoint to obtain the contents of an access token.
 *
 * If the endpoint returns a 400 response, this indicates that the token is
 * invalid.
 *
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
public class RemoteTokenServices implements ResourceServerTokenServices {

    protected final Log logger = LogFactory.getLog(getClass());

    private RestOperations restTemplate;

    private String checkTokenEndpointUrl;

    private String clientId;

    private String clientSecret;

    private boolean storeClaims = false;

    public RemoteTokenServices() {
        restTemplate = new RestTemplate();
        ((RestTemplate) restTemplate).setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            // Ignore 400
            public void handleError(ClientHttpResponse response) throws IOException {
                if (response.getRawStatusCode() != 400) {
                    super.handleError(response);
                }
            }
        });
    }

    public boolean isStoreClaims() {
        return storeClaims;
    }

    /**
     * Set to true to include all claims received from the UAA /check_token endpoint as string request parameters
     * accessible through OAuth2Authentication.getOAuth2Request().getRequestParameters()
     * @param storeClaims
     */
    public void setStoreClaims(boolean storeClaims) {
        this.storeClaims = storeClaims;
    }

    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("token", accessToken);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));
        Map<String, Object> map = postForMap(checkTokenEndpointUrl, formData, headers);

        if (map.containsKey("error")) {
            logger.debug("check_token returned error: " + map.get("error"));
            throw new InvalidTokenException(accessToken);
        }

        Assert.state(map.containsKey("client_id"), "Client id must be present in response from auth server");
        String remoteClientId = (String) map.get("client_id");

        Set<String> scope = new HashSet<String>();
        if (map.containsKey("scope")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) map.get("scope");
            scope.addAll(values);
        }
        AuthorizationRequest clientAuthentication = new AuthorizationRequest(remoteClientId, scope);

        if (map.containsKey("resource_ids") || map.containsKey("client_authorities")) {
            Set<String> resourceIds = new HashSet<String>();
            if (map.containsKey("resource_ids")) {
                @SuppressWarnings("unchecked")
                Collection<String> values = (Collection<String>) map.get("resource_ids");
                resourceIds.addAll(values);
            }
            Set<GrantedAuthority> clientAuthorities = new HashSet<GrantedAuthority>();
            if (map.containsKey("client_authorities")) {
                @SuppressWarnings("unchecked")
                Collection<String> values = (Collection<String>) map.get("client_authorities");
                clientAuthorities.addAll(getAuthorities(values));
            }
            BaseClientDetails clientDetails = new BaseClientDetails();
            clientDetails.setClientId(remoteClientId);
            clientDetails.setResourceIds(resourceIds);
            clientDetails.setAuthorities(clientAuthorities);
            clientAuthentication.setResourceIdsAndAuthoritiesFromClientDetails(clientDetails);
        }
        Map<String, String> requestParameters = new HashMap<>();
        if (isStoreClaims()) {
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (entry.getValue()!=null && entry.getValue() instanceof String) {
                    requestParameters.put(entry.getKey(), (String)entry.getValue());
                }
            }
        }

        if (map.containsKey(Claims.ADDITIONAL_AZ_ATTR)) {
            try {
                requestParameters.put(Claims.ADDITIONAL_AZ_ATTR, JsonUtils.writeValueAsString(map.get(Claims.ADDITIONAL_AZ_ATTR)));
            } catch (JsonUtils.JsonUtilException e) {
                throw new IllegalStateException("Cannot convert access token to JSON", e);
            }
        }
        clientAuthentication.setRequestParameters(Collections.unmodifiableMap(requestParameters));

        Authentication userAuthentication = getUserAuthentication(map, scope);

        clientAuthentication.setApproved(true);
        return new OAuth2Authentication(clientAuthentication.createOAuth2Request(), userAuthentication);
    }

    private Authentication getUserAuthentication(Map<String, Object> map, Set<String> scope) {
        String username = (String) map.get("user_name");
        if (username == null) {
            return null;
        }
        Set<GrantedAuthority> userAuthorities = new HashSet<GrantedAuthority>();
        if (map.containsKey("user_authorities")) {
            @SuppressWarnings("unchecked")
            Collection<String> values = (Collection<String>) map.get("user_authorities");
            userAuthorities.addAll(getAuthorities(values));
        }
        else {
            // User authorities had better not be empty or we might mistake user
            // for unauthenticated
            userAuthorities.addAll(getAuthorities(scope));
        }
        String email = (String) map.get("email");
        String id = (String) map.get("user_id");
        return new RemoteUserAuthentication(id, username, email, userAuthorities);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    private Set<GrantedAuthority> getAuthorities(Collection<String> authorities) {
        Set<GrantedAuthority> result = new HashSet<GrantedAuthority>();
        for (String authority : authorities) {
            result.add(new SimpleGrantedAuthority(authority));
        }
        return result;
    }

    private String getAuthorizationHeader(String clientId, String clientSecret) {
        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }

    private Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }
        @SuppressWarnings("rawtypes")
        Map map = restTemplate.exchange(path, HttpMethod.POST,
                        new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
        @SuppressWarnings("unchecked")
        Map<String, Object> result = map;
        return result;
    }

}
