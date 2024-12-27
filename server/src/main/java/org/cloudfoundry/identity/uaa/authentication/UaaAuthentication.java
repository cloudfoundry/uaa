/*
 * *****************************************************************************
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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyMap;

/**
 * Authentication token which represents a user.
 */
@JsonSerialize(using = UaaAuthenticationSerializer.class)
@JsonDeserialize(using = UaaAuthenticationDeserializer.class)
@Getter
@Setter
@ToString
public class UaaAuthentication extends AbstractAuthenticationToken
        implements Authentication, Serializable {

    private final Object credentials;
    private final UaaPrincipal principal;
    private long authenticatedTime = -1L;
    private long expiresAt = -1L;
    private Set<String> externalGroups;
    private Set<String> authenticationMethods;
    private Set<String> authContextClassRef;
    private Long lastLoginSuccessTime;
    private String idpIdToken;

    private Map<String, List<String>> userAttributes;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the
     *                    principal represented by this authentication object.
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
        super(authorities);

        if (principal == null || authorities == null) {
            throw new IllegalArgumentException("principal and authorities must not be null");
        }
        setDetails(details);
        setAuthenticated(authenticated);
        this.principal = principal;
        this.credentials = credentials;
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

    @Override
    public String getName() {
        // Should we return the ID for the principal name? (No, because the
        // UaaUserDatabase retrieves users by name.)
        return principal.getName();
    }

    public UaaAuthenticationDetails getUaaAuthenticationDetails() {
        return (UaaAuthenticationDetails) getDetails();
    }

    @Override
    public boolean isAuthenticated() {
        return super.isAuthenticated() && (expiresAt <= 0 || expiresAt > System.currentTimeMillis());
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

        if (!getAuthorities().equals(that.getAuthorities())) {
            return false;
        }
        return principal.equals(that.principal);
    }

    @Override
    public int hashCode() {
        int result = getAuthorities().hashCode();
        result = 31 * result + principal.hashCode();
        return result;
    }

    public MultiValueMap<String, String> getUserAttributes() {
        return new LinkedMultiValueMap<>(userAttributes != null ? userAttributes : emptyMap());
    }

    public void setUserAttributes(MultiValueMap<String, String> userAttributes) {
        this.userAttributes = new HashMap<>();
        this.userAttributes.putAll(userAttributes);
    }

    public Map<String, List<String>> getUserAttributesAsMap() {
        return userAttributes != null ? new HashMap<>(userAttributes) : emptyMap();
    }

    public void setAuthenticationDetails(UaaAuthenticationDetails authenticationDetails) {
        setDetails(authenticationDetails);
    }
}
