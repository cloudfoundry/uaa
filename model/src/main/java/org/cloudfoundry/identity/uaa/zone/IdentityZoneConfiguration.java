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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.cloudfoundry.identity.uaa.login.Prompt;

import java.util.Arrays;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IdentityZoneConfiguration {

    private TokenPolicy tokenPolicy = new TokenPolicy();
    private SamlConfig samlConfig = new SamlConfig();
    private Links links = new Links();
    private List<Prompt> prompts = Arrays.asList(
        new Prompt("username", "text", "Email"),
        new Prompt("password", "password", "Password"),
        new Prompt("passcode", "password", "One Time Code (Get on at /passcode)")
    );

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

    public Links getLinks() {
        return links;
    }

    public IdentityZoneConfiguration setLinks(Links links) {
        this.links = links;
        return this;
    }

    public List<Prompt> getPrompts() {
        return prompts;
    }

    public IdentityZoneConfiguration setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
        return this;
    }
}
