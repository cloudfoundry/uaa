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
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Authentication filter accepting basic authorization header and using it to
 * relay to a remote <code>/clientinfo</code> endpoint. Allows rejecting of
 * clients based on id or authorized grant type.
 * 
 * @author Dave Syer
 * 
 */
public class ClientInfoAuthenticationFilter implements Filter {

    protected final Log logger = LogFactory.getLog(getClass());

    private Set<String> allowedClients = Collections.singleton(".*");

    private Set<String> allowedGrantTypes = Collections.singleton(".*");

    private RestOperations restTemplate = new RestTemplate();

    private String clientInfoUrl;

    private AuthenticationEntryPoint authenticationEntryPoint = new BasicAuthenticationEntryPoint();

    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setClientInfoUrl(String clientInfoUrl) {
        this.clientInfoUrl = clientInfoUrl;
    }

    /**
     * @param allowedClients the allowedClients to set
     */
    public void setAllowedClients(Set<String> allowedClients) {
        this.allowedClients = new HashSet<String>(allowedClients);
    }

    /**
     * @param allowedGrantTypes the allowedGrantTypes to set
     */
    public void setAllowedGrantTypes(Set<String> allowedGrantTypes) {
        this.allowedGrantTypes = allowedGrantTypes;
    }

    /**
     * @param authenticationEntryPoint the authenticationEntryPoint to set
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    /**
     * Populates the Spring Security context with a
     * {@link UsernamePasswordAuthenticationToken} referring to the client
     * that authenticates using the basic authorization header.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
                    ServletException {

        HttpServletRequest servletRequest = (HttpServletRequest) request;
        String header = servletRequest.getHeader("Authorization");
        if (header == null || !header.startsWith("Basic ")) {
            chain.doFilter(request, response);
            return;
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", header);

        try {

            ResponseEntity<BaseClientDetails> result = restTemplate.exchange(clientInfoUrl, HttpMethod.GET,
                            new HttpEntity<Void>(headers), BaseClientDetails.class);

            ClientDetails client = result.getBody();
            String clientId = client.getClientId();
            validateClient(client);

            Authentication authResult = new UsernamePasswordAuthenticationToken(clientId, "<NONE>",
                            client.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authResult);

        } catch (RuntimeException e) {
            logger.debug("Authentication failed");
            authenticationEntryPoint.commence(servletRequest, (HttpServletResponse) response,
                            new BadCredentialsException("Could not authenticate", e));
            return;
        }

        chain.doFilter(request, response);

    }

    protected void validateClient(ClientDetails client) {
        String clientId = client.getClientId();
        for (String pattern : allowedClients) {
            if (!clientId.matches(pattern)) {
                throw new BadCredentialsException("Client not permitted: " + clientId);
            }
        }
        Set<String> grantTypes = client.getAuthorizedGrantTypes();
        boolean matched = false;
        for (String pattern : allowedGrantTypes) {
            for (String grantType : grantTypes) {
                if (grantType.matches(pattern)) {
                    matched = true;
                }
            }
        }
        if (!matched) {
            throw new BadCredentialsException("Client not permitted (wrong grant type): " + clientId);
        }
    }

    protected List<GrantedAuthority> getAuthorities(Collection<String> authorities) {
        return AuthorityUtils.commaSeparatedStringToAuthorityList(StringUtils
                        .collectionToCommaDelimitedString(authorities));
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }

}
