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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.getHostIfArgIsURL;

@Configuration("UaaIdpConfiguration")
public class FileIdentityProviderConfiguration extends BaseSamlFileConfiguration {

    private boolean wantAuthnRequestsSigned;
    private String entityId;
    private String entityAlias;
    private boolean signAssertions;
    private int assertionTtlSeconds;
    private String metadataUrl;

    @Value("${login.saml.wantAuthnRequestSigned:false}")
    public FileIdentityProviderConfiguration setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
        this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
        return this;
    }

    @Value("${login.idp.entityID:${login.entityID:unit-test-idp}}")
    public FileIdentityProviderConfiguration setEntityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    @Value("${login.saml.idp.entityIDAlias:${login.idp.entityID:${login.saml.entityIDAlias:${login.entityID:unit-test-idp}}}}")
    public FileIdentityProviderConfiguration setEntityAlias(String entityAlias) {
        this.entityAlias = entityAlias;
        return this;
    }

    @Value("${login.saml.idp.assertionSigned:true}")
    public FileIdentityProviderConfiguration setSignAssertions(boolean signAssertions) {
        this.signAssertions = signAssertions;
        return this;
    }


    @Value("${login.saml.idp.assertionTimeToLiveSeconds:600}")
    public FileIdentityProviderConfiguration setAssertionTtlSeconds(int assertionTtlSeconds) {
        this.assertionTtlSeconds = assertionTtlSeconds;
        return this;
    }

    @Value("${login.idpMetadataURL:null}")
    public FileIdentityProviderConfiguration setMetadataUrl(String metadataUrl) {
        this.metadataUrl = metadataUrl;
        return this;
    }


    public String getEntityAlias() {
        return getHostIfArgIsURL(entityAlias);
    }

    public boolean isWantAuthnRequestsSigned() {
        return wantAuthnRequestsSigned;
    }

    public String getEntityId() {
        return entityId;
    }

    public boolean isSignAssertions() {
        return signAssertions;
    }

    public int getAssertionTtlSeconds() {
        return assertionTtlSeconds;
    }
}
