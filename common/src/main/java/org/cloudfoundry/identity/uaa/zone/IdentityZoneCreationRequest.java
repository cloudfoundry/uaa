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
package org.cloudfoundry.identity.uaa.zone;

import java.util.List;

import javax.validation.Valid;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

@JsonDeserialize
public class IdentityZoneCreationRequest {

    @Valid
    @JsonProperty("identity_zone")
    private IdentityZone identityZone;

    @JsonProperty("client_details")
    private List<BaseClientDetails> clientDetails;

    public IdentityZone getIdentityZone() {
        return identityZone;
    }
    public void setIdentityZone(IdentityZone identityZone) {
        this.identityZone = identityZone;
    }
    public List<BaseClientDetails> getClientDetails() {
        return clientDetails;
    }
    public void setClientDetails(List<BaseClientDetails> clientDetails) {
        this.clientDetails = clientDetails;
    }

}
