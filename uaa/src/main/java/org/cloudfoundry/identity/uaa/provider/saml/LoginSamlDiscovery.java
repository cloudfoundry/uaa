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
package org.cloudfoundry.identity.uaa.provider.saml;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;

public class LoginSamlDiscovery extends SAMLDiscovery {

    private static final Logger logger = LoggerFactory.getLogger(LoginSamlDiscovery.class);

    private MetadataManager metadata;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            super.doFilter(request, response, chain);
        } catch (UnableToFindSamlIDPException x) {
            logger.warn("Unable to find SAML IDP", x);
            HttpServletResponse httpServletResponse = (HttpServletResponse)response;
            HttpServletRequest httpServletRequest = (HttpServletRequest)request;
            httpServletResponse.sendRedirect(
                httpServletResponse.encodeRedirectURL(httpServletRequest.getContextPath() + "/login?error=idp_not_found")
            );
        }
    }


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
                    String message = "Unable to read extended metadata for alias["+idpAlias+"] IDP["+idp+"]";
                    throw new UnableToFindSamlIDPException(message, e);
                }
            }
        }
        throw new UnableToFindSamlIDPException("Unable to locate IDP provider for alias:"+idpAlias);
        //return super.getPassiveIDP(request);
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

    public static class UnableToFindSamlIDPException extends RuntimeException {
        public UnableToFindSamlIDPException(String message) {
            super(message);
        }

        public UnableToFindSamlIDPException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
