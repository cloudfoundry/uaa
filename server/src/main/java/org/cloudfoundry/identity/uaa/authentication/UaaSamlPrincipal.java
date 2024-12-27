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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

import java.io.Serializable;
import java.util.List;

/**
 * UaaSamlPrincipal extends {@link UaaPrincipal} and adds the {@link Saml2AuthenticatedPrincipal} interface.
 * Notably, it allows retrieval of the relying party registration id.
 * <p/>
 * This is used to represent a SAML principal in the {@link UaaAuthentication} Object.
 * The SAML Logout Handlers check if the Principal is an instance of Saml2AuthenticatedPrincipal to handle SAML Logout.
 */
@ToString(callSuper = true)
@JsonIgnoreProperties({"relyingPartyRegistrationId", "sessionIndexes", "attributes"})
public class UaaSamlPrincipal extends UaaPrincipal implements Saml2AuthenticatedPrincipal, Serializable {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final List<String>  sessionIndexes;

    public UaaSamlPrincipal(UaaUser user, List<String> sessionIndexes) {
        super(user);
        this.sessionIndexes = sessionIndexes;
    }

    @JsonCreator
    public UaaSamlPrincipal(
            @JsonProperty("id") String id,
            @JsonProperty("name") String username,
            @JsonProperty("email") String email,
            @JsonProperty("origin") String origin,
            @JsonProperty("sessionIndexes") List<String> sessionIndexes,
            @JsonProperty("externalId") String externalId,
            @JsonProperty("zoneId") String zoneId) {
        super(id, username, email, origin, externalId, zoneId);
        this.sessionIndexes = sessionIndexes;
    }

    @Override
    public String getRelyingPartyRegistrationId() {
        return getOrigin();
    }

    @Override
    public List<String> getSessionIndexes() {
        return sessionIndexes;
    }
}
