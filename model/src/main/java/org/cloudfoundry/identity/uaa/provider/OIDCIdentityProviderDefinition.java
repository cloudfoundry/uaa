/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URL;
import java.util.List;


@JsonIgnoreProperties(ignoreUnknown = true)
public class OIDCIdentityProviderDefinition extends AbstractXOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition>
implements Cloneable {

    public enum OIDCGrantType {
        @JsonProperty("password")
        password,
        @JsonProperty("authorization_code")
        authorization_code,
        @JsonProperty("implicit")
        implicit
    }

    private URL userInfoUrl;
    private URL discoveryUrl;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<OIDCGrantType> relyingPartyGrantTypes;

    public URL getUserInfoUrl() {
        return userInfoUrl;
    }

    public OIDCIdentityProviderDefinition setUserInfoUrl(URL userInfoUrl) {
        this.userInfoUrl = userInfoUrl;
        return this;
    }

    public URL getDiscoveryUrl() {
        return discoveryUrl;
    }

    public void setDiscoveryUrl(URL discoveryUrl) {
        this.discoveryUrl = discoveryUrl;
    }

    public List<OIDCGrantType> getRelyingPartyGrantTypes() {
        return relyingPartyGrantTypes;
    }

    public void setRelyingPartyGrantTypes(List<OIDCGrantType> relyingPartyGrantTypes) {
        this.relyingPartyGrantTypes = relyingPartyGrantTypes;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        OIDCIdentityProviderDefinition that = (OIDCIdentityProviderDefinition) o;

        if (userInfoUrl != null ? !userInfoUrl.equals(that.userInfoUrl) : that.userInfoUrl != null) return false;
        return discoveryUrl != null ? discoveryUrl.equals(that.discoveryUrl) : that.discoveryUrl == null;

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (userInfoUrl != null ? userInfoUrl.hashCode() : 0);
        result = 31 * result + (discoveryUrl != null ? discoveryUrl.hashCode() : 0);
        return result;
    }
}
