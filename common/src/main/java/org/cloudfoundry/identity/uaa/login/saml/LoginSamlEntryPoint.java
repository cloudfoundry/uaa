/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.saml;


import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import java.util.List;

public class LoginSamlEntryPoint extends SAMLEntryPoint {


    public void setProviderDefinitionList(List<IdentityProviderDefinition> providerDefinitionList) {
        this.providerDefinitionList = providerDefinitionList;
    }

    protected List<IdentityProviderDefinition> providerDefinitionList;

    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) throws MetadataProviderException {
        WebSSOProfileOptions options = super.getProfileOptions(context, exception);
        String idpEntityId = context.getPeerEntityId();
        if (idpEntityId!=null) {
            ExtendedMetadata extendedMetadata = this.metadata.getExtendedMetadata(idpEntityId);
            if (extendedMetadata!=null) {
                String alias = extendedMetadata.getAlias();
                IdentityProviderDefinition def = getIDPDefinition(alias);
                if (def.getNameID()!=null) {
                    options.setNameID(def.getNameID());
                }
                if (def.getAssertionConsumerIndex()>=0) {
                    options.setAssertionConsumerIndex(def.getAssertionConsumerIndex());
                }
            }
        }
        return options;
    }

    private IdentityProviderDefinition getIDPDefinition(String alias) {
        if (alias!=null) {
            for (IdentityProviderDefinition def : providerDefinitionList) {
                if (alias.equals(def.getIdpEntityAlias())) {
                    return def;
                }
            }
        }
        return null;
    }
}
