/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;

@JsonSerialize(using = CompositeAccessTokenSerializer.class)
@JsonDeserialize(using = CompositeAccessTokenDeserializer.class)
public class CompositeToken extends DefaultOAuth2AccessToken {

    public static final String ID_TOKEN = "id_token";

    public String getIdTokenValue() {
        return idTokenValue;
    }

    public void setIdTokenValue(String idTokenValue) {
        this.idTokenValue = idTokenValue;
    }

    private String idTokenValue;

    public CompositeToken(String accessTokenValue) {
        super(accessTokenValue);
    }

    public CompositeToken(OAuth2AccessToken accessToken) {
        super(accessToken);
    }
}
