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
package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdentityZoneConfiguration {
    private TokenPolicy tokenPolicy = new TokenPolicy();
    private SamlConfig samlConfig = new SamlConfig();

    public IdentityZoneConfiguration() {}

    public IdentityZoneConfiguration(TokenPolicy tokenPolicy) {
        this.tokenPolicy = tokenPolicy;
    }

    public TokenPolicy getTokenPolicy() {
        return tokenPolicy;
    }

    public void setTokenPolicy(TokenPolicy tokenPolicy) {
        this.tokenPolicy = tokenPolicy;
    }

    public SamlConfig getSamlConfig() {
        return samlConfig;
    }

    public IdentityZoneConfiguration setSamlConfig(SamlConfig samlConfig) {
        this.samlConfig = samlConfig;
        return this;
    }
}
