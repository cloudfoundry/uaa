package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

import java.util.Map;

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
public class RawOauthAuthenticationFlow implements XOAuthIdentityProviderDefinition.AuthenticationFlow {

    @Override
    @JsonIgnore
    public String getType() {
        return OriginKeys.OAUTH20;
    }

    @Override
    @JsonIgnore
    public String getResponseType() {
        return "token";
    }

    @Override
    @JsonIgnore
    public String getTokenFromResponse(Map<String, String> responseBody) {
        return responseBody.get("access_token");
    }

    private String ohmygodwhatever;

    public String getOhmygodwhatever() {
        return ohmygodwhatever;
    }

    public void setOhmygodwhatever(String ohmygodwhatever) {
        this.ohmygodwhatever = ohmygodwhatever;
    }
}
