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

import javax.servlet.http.HttpServletRequest;

import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;

public class LoginSamlDiscovery extends SAMLDiscovery {

    private static final Log logger = LogFactory.getLog(LoginSamlDiscovery.class);

    private MetadataManager metadata;

    @Override
    protected String getPassiveIDP(HttpServletRequest request) {
        String paramName = request.getParameter(RETURN_ID_PARAM);
        //we have received the alias in our request
        //so we need to translate that into an entityID
        String idpAlias = request.getParameter(paramName==null?"idp":paramName);
        if ( idpAlias!=null ) {
            Set<String> idps = metadata.getIDPEntityNames();
            for (String idp : idps) {
                try {
                    ExtendedMetadata emd = metadata.getExtendedMetadata(idp);
                    if (emd!=null && idpAlias.equals(emd.getAlias())) {
                        return idp;
                    }
                } catch (MetadataProviderException e) {
                    logger.warn("Unable to read extended metadata for alias["+idpAlias+"] IDP["+idp+"]", e);
                }
            }
        }
        return super.getPassiveIDP(request);
    }

    @Override
    @Autowired
    public void setMetadata(MetadataManager metadata) {
        super.setMetadata(metadata);
        this.metadata = metadata;
    }

    @Override
    @Autowired(required = false)
    public void setSamlEntryPoint(SAMLEntryPoint samlEntryPoint) {
        super.setSamlEntryPoint(samlEntryPoint);
    }

    @Override
    @Autowired
    public void setContextProvider(SAMLContextProvider contextProvider) {
        super.setContextProvider(contextProvider);
    }
}
