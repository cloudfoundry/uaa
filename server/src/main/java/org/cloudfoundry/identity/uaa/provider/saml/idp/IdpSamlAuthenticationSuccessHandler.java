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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.opensaml.common.SAMLException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

/**
 * Use this class in conjunction with
 * org.springframework.security.saml.SAMLProcessingFilter to create a SAML
 * Response after SAMLProcessingFilter successfully processes a SAML
 * Authentication Request.
 */
public class IdpSamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(IdpSamlAuthenticationSuccessHandler.class);

    private IdpWebSsoProfile idpWebSsoProfile;
    private MetadataManager metadataManager;

    public IdpSamlAuthenticationSuccessHandler() {
        super();
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws ServletException {

        SAMLMessageContext context = ((UaaAuthentication) authentication).getSamlMessageContext();

        IdpExtendedMetadata extendedMetadata = null;
        try {
            extendedMetadata = (IdpExtendedMetadata) metadataManager.getExtendedMetadata(context.getLocalEntityId());
        } catch (MetadataProviderException e) {
            throw new ServletException("Failed to obtain local SAML IdP extended metadata.", e);
        }

        try {
            populatePeerContext(context);
        } catch (MetadataProviderException e) {
            throw new ServletException("Failed to populate peer SAML SP context.", e);
        }

        try {
            IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
            options.setAssertionsSigned(extendedMetadata.isAssertionsSigned());
            options.setAssertionTimeToLiveSeconds(extendedMetadata.getAssertionTimeToLiveSeconds());
            idpWebSsoProfile.sendResponse(authentication, context, options);
        } catch (SAMLException e) {
            LOGGER.debug("Incoming SAML message is invalid.", e);
            throw new AuthenticationServiceException("Incoming SAML message is invalid.", e);
        } catch (MetadataProviderException e) {
            LOGGER.debug("Error determining metadata contracts.", e);
            throw new AuthenticationServiceException("Error determining metadata contracts.", e);
        } catch (MessageEncodingException e) {
            LOGGER.debug("Error decoding incoming SAML message.", e);
            throw new AuthenticationServiceException("Error encoding outgoing SAML message.", e);
        } catch (MarshallingException | SecurityException | SignatureException e) {
            LOGGER.debug("Error signing SAML assertion.", e);
            throw new AuthenticationServiceException("Error signing SAML assertion.", e);
        }
    }

    protected void populatePeerContext(SAMLMessageContext samlContext) throws MetadataProviderException {

        String peerEntityId = samlContext.getPeerEntityId();
        QName peerEntityRole = samlContext.getPeerEntityRole();

        if (peerEntityId == null) {
            throw new MetadataProviderException("Peer entity ID wasn't specified, but is requested");
        }

        EntityDescriptor entityDescriptor = metadataManager.getEntityDescriptor(peerEntityId);
        RoleDescriptor roleDescriptor = metadataManager.getRole(peerEntityId, peerEntityRole, SAMLConstants.SAML20P_NS);
        ExtendedMetadata extendedMetadata = metadataManager.getExtendedMetadata(peerEntityId);

        if (entityDescriptor == null || roleDescriptor == null) {
            throw new MetadataProviderException(
                    "Metadata for entity " + peerEntityId + " and role " + peerEntityRole + " wasn't found");
        }

        samlContext.setPeerEntityMetadata(entityDescriptor);
        samlContext.setPeerEntityRoleMetadata(roleDescriptor);
        samlContext.setPeerExtendedMetadata(extendedMetadata);
    }

    @Autowired
    public void setIdpWebSsoProfile(IdpWebSsoProfile idpWebSsoProfile) {
        Assert.notNull(idpWebSsoProfile, "SAML Web SSO profile can't be null.");
        this.idpWebSsoProfile = idpWebSsoProfile;
    }

    @Autowired
    public void setMetadataManager(MetadataManager metadataManager) {
        Assert.notNull(metadataManager, "SAML metadata manager can't be null.");
        this.metadataManager = metadataManager;
    }
}
