/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.xml.security.credential.Credential;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.trust.MetadataCredentialResolver;

import java.util.Collection;


public class NonCachingMetadataCredentialResolver extends MetadataCredentialResolver {

    public NonCachingMetadataCredentialResolver(MetadataManager metadataProvider, KeyManager keyManager) {
        super(metadataProvider, keyManager);
    }

    @Override
    protected void cacheCredentials(MetadataCacheKey cacheKey, Collection<Credential> credentials) {
        //no op
    }
}
