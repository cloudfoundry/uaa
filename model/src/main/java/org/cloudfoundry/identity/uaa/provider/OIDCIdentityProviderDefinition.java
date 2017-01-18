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

import java.net.URL;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;


@JsonIgnoreProperties(ignoreUnknown = true)
public class OIDCIdentityProviderDefinition extends AbstractXOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> {

    private URL userInfoUrl;
    private URL discoveryUrl;

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
}
