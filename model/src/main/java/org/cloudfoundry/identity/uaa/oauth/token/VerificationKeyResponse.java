/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;

import java.util.Map;

@Deprecated
/**
 * Use {@link JsonWebKey}
 */
public class VerificationKeyResponse extends JsonWebKey {


    public VerificationKeyResponse(Map<String, Object> json) {
        super(json);
    }

    @JsonIgnore
    public String getId() {
        return getKid();
    }

    @JsonIgnore
    public String getAlgorithm() {
        return (String) getKeyProperties().get("alg");
    }

    @JsonIgnore
    public String getKey() {
        return (String) getKeyProperties().get("value");
    }

    @JsonIgnore
    public String getType() {
        return getKty().name();
    }

    @JsonIgnore
    public String getKeyUse() {
        return getUse().name();
    }

    @JsonIgnore
    public String[] getCertX5c() {
        return getX5c();
    }

    @JsonIgnore
    public String getCertX5t() {
        return getX5t();
    }

    @JsonIgnore
    public String getModulus() {
        return (String) getKeyProperties().get("n");
    }

    @JsonIgnore
    public String getExponent() {
        return (String) getKeyProperties().get("e");
    }

}

