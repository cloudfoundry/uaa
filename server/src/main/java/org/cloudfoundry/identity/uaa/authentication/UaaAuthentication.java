/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static java.util.Collections.EMPTY_MAP;

/**
 * Authentication token which represents a user.
 */
@JsonSerialize(using = UaaAuthenticationSerializer.class)
@JsonDeserialize(using = UaaAuthenticationDeserializer.class)
public class UaaAuthentication implements Authentication, Serializable {

    private Collection<? extends GrantedAuthority> authorities;
    private Object credentials;
    private UaaPrincipal principal;
    private UaaAuthenticationDetails details;
    private boolean authenticated;
    private long authenticatedTime = -1L;
    private long expiresAt = -1L;
    private Set<String> externalGroups;
    private Set<String> authenticationMethods;
    private Set<String> authContextClassRef;
    private Long lastLoginSuccessTime;

    private Map userAttributes;

    public Long getLastLoginSuccessTime() {
        return lastLoginSuccessTime;
    }

    public UaaAuthentication setLastLoginSuccessTime(Long lastLoginSuccessTime) {
        this.lastLoginSuccessTime = lastLoginSuccessTime;
        return this;
    }

    //This is used when UAA acts as a SAML IdP
    @JsonIgnore
    private transient SAMLMessageContext samlMessageContext;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the
     *            principal represented by this authentication object.
     */
    public UaaAuthentication(UaaPrincipal principal,
                             Collection<? extends GrantedAuthority> authorities,
                             UaaAuthenticationDetails details) {
        this(principal, null, authorities, details, true, System.currentTimeMillis());
    }

    public UaaAuthentication(UaaPrincipal principal,
                             Object credentials,
                             Collection<? extends GrantedAuthority> authorities,
                             UaaAuthenticationDetails details,
                             boolean authenticated,
                             long authenticatedTime) {
        this(principal, credentials, authorities, details, authenticated, authenticatedTime, -1);
    }

    public UaaAuthentication(UaaPrincipal principal,
                             Object credentials,
                             Collection<? extends GrantedAuthority> authorities,
                             UaaAuthenticationDetails details,
                             boolean authenticated,
                             long authenticatedTime,
                             long expiresAt) {
        if (principal == null || authorities == null) {
            throw new IllegalArgumentException("principal and authorities must not be null");
        }
        this.principal = principal;
        this.authorities = authorities;
        this.details = details;
        this.credentials = credentials;
        this.authenticated = authenticated;
        this.authenticatedTime = authenticatedTime <= 0 ? -1 : authenticatedTime;
        this.expiresAt = expiresAt <= 0 ? -1 : expiresAt;
    }

    public UaaAuthentication(UaaPrincipal uaaPrincipal,
                             Object credentials,
                             List<? extends GrantedAuthority> uaaAuthorityList,
                             Set<String> externalGroups,
                             Map<String, List<String>> userAttributes,
                             UaaAuthenticationDetails details,
                             boolean authenticated,
                             long authenticatedTime,
                             long expiresAt) {
        this(uaaPrincipal, credentials, uaaAuthorityList, details, authenticated, authenticatedTime, expiresAt);
        this.externalGroups = externalGroups;
        this.userAttributes = new HashMap<>(userAttributes);
    }

    public long getAuthenticatedTime() {
        return authenticatedTime;
    }

    @Override
    public String getName() {
        // Should we return the ID for the principal name? (No, because the
        // UaaUserDatabase retrieves users by name.)
        return principal.getName();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public UaaPrincipal getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated && (expiresAt > 0 ? expiresAt > System.currentTimeMillis() : true);
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        authenticated = isAuthenticated;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        UaaAuthentication that = (UaaAuthentication) o;

        if (!authorities.equals(that.authorities)) {
            return false;
        }
        if (!principal.equals(that.principal)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = authorities.hashCode();
        result = 31 * result + principal.hashCode();
        return result;
    }

    public Set<String> getExternalGroups() {
        return externalGroups;
    }

    public void setExternalGroups(Set<String> externalGroups) {
        this.externalGroups = externalGroups;
    }

    public MultiValueMap<String,String> getUserAttributes() {
        return new LinkedMultiValueMap<>(userAttributes!=null? userAttributes: EMPTY_MAP);
    }

    public Map<String,List<String>> getUserAttributesAsMap() {
        return userAttributes!=null ? new HashMap<>(userAttributes) : EMPTY_MAP;
    }

    public void setUserAttributes(MultiValueMap<String, String> userAttributes) {
        this.userAttributes = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : userAttributes.entrySet()) {
            this.userAttributes.put(entry.getKey(), entry.getValue());
        }
    }

    @JsonIgnore
    public SAMLMessageContext getSamlMessageContext() {
        return samlMessageContext;
    }

    @JsonIgnore
    public void setSamlMessageContext(SAMLMessageContext samlMessageContext) {
        this.samlMessageContext = samlMessageContext;
    }

    public Set<String> getAuthenticationMethods() {
        return authenticationMethods;
    }

    public void setAuthenticationMethods(Set<String> authenticationMethods) {
        this.authenticationMethods = authenticationMethods;
    }

    public Set<String> getAuthContextClassRef() {
        return authContextClassRef;
    }

    public void setAuthContextClassRef(Set<String> authContextClassRef) {
        this.authContextClassRef = authContextClassRef;
    }

    public void setAuthenticatedTime(long authenticatedTime) {
        this.authenticatedTime = authenticatedTime;
    }

    public void setAuthenticationDetails(UaaAuthenticationDetails authenticationDetails) {
        this.details = authenticationDetails;
    }
}
