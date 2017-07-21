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


import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.FilterInvocation;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LoginSamlEntryPoint extends SAMLEntryPoint {


    private SamlIdentityProviderConfigurator providerDefinitionList;

    public SamlIdentityProviderConfigurator getProviderDefinitionList() {
        return providerDefinitionList;
    }

    public void setProviderDefinitionList(SamlIdentityProviderConfigurator providerDefinitionList) {
        this.providerDefinitionList = providerDefinitionList;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(request, response, chain);

        if (!processFilter(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            commence(fi.getRequest(), fi.getResponse(), null);
        } catch (ServletException e) {
            if(e.getRootCause() instanceof MetadataProviderException) {
                request.setAttribute("error_message_code", "no.sso.supported.binding");
                ((HttpServletResponse)response).sendError(HttpStatus.BAD_REQUEST.value(), "Bad Request:" +
                        " Please Check the Identity Provider for compatible SSO bindings ");
                return;
            } else {
                throw e;
            }
        }
    }

    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) throws MetadataProviderException {
        WebSSOProfileOptions options = super.getProfileOptions(context, exception);
        String idpEntityId = context.getPeerEntityId();
        if (idpEntityId!=null) {
            ExtendedMetadata extendedMetadata = this.metadata.getExtendedMetadata(idpEntityId);
            if (extendedMetadata!=null) {
                String alias = extendedMetadata.getAlias();
                SamlIdentityProviderDefinition def = getIDPDefinition(alias);
                if (def.getNameID()!=null) {
                    options.setNameID(def.getNameID());
                }
                if (def.getAssertionConsumerIndex()>=0) {
                    options.setAssertionConsumerIndex(def.getAssertionConsumerIndex());
                }

                if (def.getAuthnContext() != null) {
                    options.setAuthnContexts(def.getAuthnContext());
                }
            }
        }
        return options;
    }

    private SamlIdentityProviderDefinition getIDPDefinition(String alias) throws MetadataProviderException {
        if (alias!=null) {
            for (SamlIdentityProviderDefinition def : getProviderDefinitionList().getIdentityProviderDefinitions()) {
                if (alias.equals(def.getIdpEntityAlias()) && IdentityZoneHolder.get().getId().equals(def.getZoneId())) {
                    return def;
                }
            }
        }
        throw new MetadataProviderNotFoundException("Unable to find SAML provider for alias:"+alias);
    }
}
