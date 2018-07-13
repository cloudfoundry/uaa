/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import java.util.Map;

import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import static java.lang.Boolean.parseBoolean;
import static java.lang.Integer.parseInt;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getHostIfArgIsURL;
import static org.springframework.util.StringUtils.hasText;

@Configuration("UaaSpConfiguration")
public class FileServiceProviderConfiguration extends BaseSamlFileConfiguration {


    private String entityId;
    private String entityAlias;
    private boolean wantAssertionsSigned;
    private String authnRequestNameId;
    private String relayState;
    private int assertionConsumerIndex;
    private long maxAuthenticationAge;

    @Value("${login.entityID:unit-test-sp}")
    public FileServiceProviderConfiguration setEntityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    @Value("${login.saml.entityIDAlias:${login.entityID:unit-test-sp}}")
    public FileServiceProviderConfiguration setEntityAlias(String entityAlias) {
        this.entityAlias = entityAlias;
        return this;
    }

    @Value("${login.saml.wantAssertionSigned:true}")
    public FileServiceProviderConfiguration setWantAssertionsSigned(boolean wantAssertionsSigned) {
        this.wantAssertionsSigned = wantAssertionsSigned;
        return this;
    }

    @Value("${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}")
    public FileServiceProviderConfiguration setAuthnRequestNameId(String authnRequestNameId) {
        this.authnRequestNameId = authnRequestNameId;
        return this;
    }

    @Value("${login.saml.relayState:cloudfoundry-uaa-sp}")
    public FileServiceProviderConfiguration setRelayState(String relayState) {
        this.relayState = relayState;
        return this;
    }

    @Value("${login.saml.assertionConsumerIndex:0}")
    public FileServiceProviderConfiguration setAssertionConsumerIndex(int assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
        return this;
    }

    @Value("${login.saml.maxAuthenticationAge:864000}")
    public FileServiceProviderConfiguration setMaxAuthenticationAge(long maxAuthenticationAge) {
        this.maxAuthenticationAge = maxAuthenticationAge;
        return this;
    }

    @Bean("samlSPAlias")
    public String getEntityAlias() {
        return getHostIfArgIsURL(entityAlias);
    }

    @Bean("samlEntityID")
    public String getEntityId() {
        return entityId;
    }

    @Bean
    public BootstrapSamlIdentityProviderData bootstrapMetaDataProviders(Environment env) {
        BootstrapSamlIdentityProviderData providerData = new BootstrapSamlIdentityProviderData();
        @SuppressWarnings("checked")
        Map<String,Map<String,Object>> providers = env.getProperty("login.saml.providers", Map.class);
        providerData.setIdentityProviders(providers);

        //no longer supporting the config for a single provider - remove
        String legacyIdpUrl = env.getProperty("login.idpMetadataURL");
        String legacyIdpMetadata = env.getProperty("login.idpMetadata");
        providerData.setLegacyIdpMetaData(hasText(legacyIdpMetadata) ? legacyIdpMetadata : legacyIdpUrl);
        providerData.setLegacyIdpIdentityAlias(env.getProperty("login.idpEntityAlias"));
        providerData.setLegacyAssertionConsumerIndex(parseInt(env.getProperty("login.assertionConsumerIndex","0")));
        providerData.setLegacyShowSamlLink(parseBoolean(env.getProperty("login.showSamlLoginLink","true")));
        providerData.setLegacyMetadataTrustCheck(parseBoolean(env.getProperty("login.saml.metadataTrustCheck","true")));

        return providerData;
    }

    public boolean isWantAssertionsSigned() {
        return wantAssertionsSigned;
    }

    public String getAuthnRequestNameId() {
        return authnRequestNameId;
    }

    public String getRelayState() {
        return relayState;
    }

    public int getAssertionConsumerIndex() {
        return assertionConsumerIndex;
    }

    public long getMaxAuthenticationAge() {
        return maxAuthenticationAge;
    }
}
