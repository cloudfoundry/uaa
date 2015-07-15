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
package org.cloudfoundry.identity.uaa.authentication;

import java.io.Serializable;
import java.security.Principal;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * The principal object which should end up as the representation of an
 * authenticated user.
 * <p>
 * Contains the data required for an authenticated user within the UAA
 * application itself.
 */
public class UaaPrincipal implements Principal, Serializable {
    private final String id;
    private final String name;
    private final String email;
    private final String origin;
    private final String externalId;
    private final String zoneId;

    public UaaPrincipal(UaaUser user) {
        this(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.getOrigin(),
            user.getExternalId(),
            user.getZoneId()
        );
    }

    @JsonCreator
    public UaaPrincipal(
        @JsonProperty("id") String id,
        @JsonProperty("name") String username,
        @JsonProperty("email") String email,
        @JsonProperty("origin") String origin,
        @JsonProperty("externalId") String externalId,
        @JsonProperty("zoneId") String zoneId) {
        this.id = id;
        this.name = username;
        this.email = email;
        this.origin = origin;
        this.externalId = externalId;
        this.zoneId = zoneId;
    }

    public String getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getOrigin() { return origin; }

    public String getExternalId() { return externalId; }

    public String getZoneId() { return zoneId; }

    /**
     * Returns {@code true} if the supplied object is a {@code UAAPrincipal}
     * instance with the
     * same {@code id} value.
     * <p>
     * In other words, the objects are equal if they have the same user id,
     * representing the same principal.
     */
    @Override
    public boolean equals(Object rhs) {
        if (rhs instanceof UaaPrincipal) {
            return id.equals(((UaaPrincipal) rhs).id);
        }
        return false;
    }

    /**
     * Returns the hashcode of the {@code id}.
     */
    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
