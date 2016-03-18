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

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

import java.net.URL;
import java.util.Map;

public class OidcAuthenticationFlow implements XOAuthIdentityProviderDefinition.AuthenticationFlow {

    private URL userInfoUrl;

    @Override
    @JsonIgnore
    public String getType() {
        return OriginKeys.OIDC10;
    }

    @Override
    @JsonIgnore
    public String getResponseType() {
        return "id_token";
    }

    @Override
    @JsonIgnore
    public String getTokenFromResponse(Map<String, String> responseBody) {
        return responseBody.get("id_token");
    }

    public OidcAuthenticationFlow setUserInfoUrl(URL userInfoUrl) {
        this.userInfoUrl = userInfoUrl;
        return this;
    }

    public URL getUserInfoUrl() {
        return userInfoUrl;
    }
}
