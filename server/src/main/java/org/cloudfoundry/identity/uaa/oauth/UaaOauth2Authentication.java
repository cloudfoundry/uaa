/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;


import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.springframework.security.core.Authentication;

public class UaaOauth2Authentication extends OAuth2Authentication {

    private final String zoneId;
    private final String tokenValue;

    public UaaOauth2Authentication(String tokenValue, String zoneId, OAuth2Request storedRequest, Authentication userAuthentication) {
        super(storedRequest, userAuthentication);
        this.zoneId = zoneId;
        this.tokenValue = tokenValue;
    }

    public String getZoneId() {
        return zoneId;
    }

    public String getTokenValue() {
        return tokenValue;
    }
}
