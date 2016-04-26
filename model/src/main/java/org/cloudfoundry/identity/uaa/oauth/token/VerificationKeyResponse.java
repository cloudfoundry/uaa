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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * Created by pivotal on 11/18/15.
 */
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE)
public class VerificationKeyResponse {

    @JsonProperty("kid")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String kid;

    @JsonProperty("alg")
    private String algorithm;

    @JsonProperty("value")
    private String key;

    @JsonProperty("kty")
    private String type;

    @JsonProperty("use")
    private String use;

    @JsonProperty("n")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String modulus;

    @JsonProperty("e")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String exponent;

    public String getId() {
        return kid;
    }

    public void setId(String kid) {
        this.kid = kid;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getUse() {
        return use;
    }

    public void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getModulus() {
        return modulus;
    }

    public void setExponent(String exponent) {
        this.exponent = exponent;
    }

    public String getExponent() {
        return exponent;
    }

}

