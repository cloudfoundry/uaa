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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * Use this class in conjuction with
 * org.springframework.security.saml.SAMLProcessingFilter to ensure that when
 * SAMLProcessingFilter processes a SAML Authentication Request and builds a
 * SAMLMessageContext it identifies the peer entity as a SAML SP.
 */
public class IdpSamlContextProviderImpl extends SAMLContextProviderImpl {

    @Override
    public SAMLMessageContext getLocalEntity(HttpServletRequest request, HttpServletResponse response)
            throws MetadataProviderException {
        SAMLMessageContext context = super.getLocalEntity(new TestRequestWrapper(request), new TestResponseWrapper(response));
        context.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        return context;
    }

    /**
     * Method tries to load localEntityAlias and localEntityRole from the request path. Path is supposed to be in format:
     * https(s)://server:port/application/saml/filterName/alias/aliasName/idp|sp. In case alias is missing from
     * the path defaults are used. Otherwise localEntityId and sp or idp localEntityRole is entered into the context.
     * <p>
     * In case alias entity id isn't found an exception is raised.
     *
     * @param context     context to populate fields localEntityId and localEntityRole for
     * @param requestURI context path to parse entityId and entityRole from
     * @throws MetadataProviderException in case entityId can't be populated
     */
    @Override
    protected void populateLocalEntityId(SAMLMessageContext context, String requestURI) throws MetadataProviderException {

        String entityId;
        HTTPInTransport inTransport = (HTTPInTransport) context.getInboundMessageTransport();

        // Pre-configured entity Id
        entityId = (String) inTransport.getAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_ENTITY_ID);
        if (entityId != null) {
            log.debug("Using protocol specified IdP {}", entityId);
            context.setLocalEntityId(entityId);
            context.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
            return;
        }

        if (requestURI == null) {
            requestURI = "";
        }

        int filterIndex = requestURI.indexOf("/alias/");
        if (filterIndex != -1) { // EntityId from URL alias

            String localAlias = requestURI.substring(filterIndex + 7);
            QName localEntityRole;

            int entityTypePosition = localAlias.lastIndexOf('/');
            if (entityTypePosition != -1) {
                String entityRole = localAlias.substring(entityTypePosition + 1);
                if ("sp".equalsIgnoreCase(entityRole)) {
                    localEntityRole = SPSSODescriptor.DEFAULT_ELEMENT_NAME;
                } else {
                    localEntityRole = IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
                }
                localAlias = localAlias.substring(0, entityTypePosition);
            } else {
                localEntityRole = IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
            }


            // Populate entityId
            entityId = metadata.getEntityIdForAlias(localAlias);

            if (entityId == null) {
                throw new MetadataProviderException("No local entity found for alias " + localAlias + ", verify your configuration.");
            } else {
                log.debug("Using IdP {} specified in request with alias {}", entityId, localAlias);
            }

            context.setLocalEntityId(entityId);
            context.setLocalEntityRole(localEntityRole);

        } else { // Defaults
            context.setLocalEntityId(metadata.getDefaultIDP());
            context.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        }

    }

}
