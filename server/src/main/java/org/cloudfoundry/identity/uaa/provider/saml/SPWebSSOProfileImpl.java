/*******************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import static org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;

public class SPWebSSOProfileImpl extends WebSSOProfileImpl {
    public SPWebSSOProfileImpl () {}

    public SPWebSSOProfileImpl(SAMLProcessor processor, MetadataManager manager) {
        super(processor, manager);
    }

    /**
     * Determines whether given SingleSignOn service can be used together with this profile. Bindings POST, Artifact
     * and Redirect are supported for WebSSO.
     *
     * @param endpoint endpoint
     * @return true if endpoint is supported
     */
    @Override
    protected boolean isEndpointSupported(SingleSignOnService endpoint) {
        return
            SAML2_POST_BINDING_URI.equals(endpoint.getBinding()) ||
            SAML2_REDIRECT_BINDING_URI.equals(endpoint.getBinding());
    }

    @Override
    protected SingleSignOnService getSingleSignOnService(WebSSOProfileOptions options, IDPSSODescriptor idpssoDescriptor, SPSSODescriptor spDescriptor) throws MetadataProviderException {
        try {
            return super.getSingleSignOnService(options, idpssoDescriptor, spDescriptor);
        } catch (MetadataProviderException e) {
            throw new SamlBindingNotSupportedException(e.getMessage(), e);
        }
    }
}
