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
import lombok.Data;
import org.cloudfoundry.identity.uaa.login.Prompt;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class IdentityZoneConfiguration {

    private static final String PASSWORD = "password";

    private ClientSecretPolicy clientSecretPolicy = new ClientSecretPolicy();
    private TokenPolicy tokenPolicy = new TokenPolicy();
    private SamlConfig samlConfig = new SamlConfig();
    private CorsPolicy corsPolicy = new CorsPolicy();
    private Links links = new Links();
    private List<Prompt> prompts = Arrays.asList(
            new Prompt("username", "text", "Email"),
            new Prompt(PASSWORD, PASSWORD, "Password"),
            new Prompt("passcode", PASSWORD, "Temporary Authentication Code (Get on at /passcode)")
    );
    private boolean idpDiscoveryEnabled;
    private BrandingInformation branding;
    private boolean accountChooserEnabled;
    private UserConfig userConfig = new UserConfig();
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String issuer;
    private String defaultIdentityProvider;

    public IdentityZoneConfiguration() {
    }

    public IdentityZoneConfiguration(TokenPolicy tokenPolicy) {
        this.tokenPolicy = tokenPolicy;
    }

    public IdentityZoneConfiguration setSamlConfig(SamlConfig samlConfig) {
        this.samlConfig = samlConfig;
        return this;
    }

    public IdentityZoneConfiguration setLinks(Links links) {
        this.links = links;
        return this;
    }

    public IdentityZoneConfiguration setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
        return this;
    }

    public IdentityZoneConfiguration setCorsPolicy(CorsPolicy corsPolicy) {
        this.corsPolicy = corsPolicy;
        return this;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public void setIssuer(String issuer) {
        try {
            new URL(issuer);
            this.issuer = issuer;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid issuer format. Must be valid URL.");
        }
    }
}
