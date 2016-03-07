/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.metadata.MetadataManager;

import java.util.List;

/**
 * MetadataManager has a field that stores the entity id of the local SAML service provider. However, in order to
 * support SAML identity provider funcationality we also need to store the entity id of the local SAML identity
 * provider. That is what this class provides.
 *
 */
public class IdpMetadataManager extends MetadataManager {

    private String hostedIdpName;

    public IdpMetadataManager(final List<MetadataProvider> providers) throws MetadataProviderException {
        super(providers);
    }

    public String getHostedIdpName() {
        return this.hostedIdpName;
    }

    public void setHostedIdpName(final String hostedIdpName) {
        this.hostedIdpName = hostedIdpName;
    }
}
