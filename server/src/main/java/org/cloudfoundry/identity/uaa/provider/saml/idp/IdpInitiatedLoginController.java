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

package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.opensaml.common.SAMLException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IndexedEndpoint;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.util.List;
import java.util.Optional;

import static org.opensaml.saml2.metadata.SPSSODescriptor.DEFAULT_ELEMENT_LOCAL_NAME;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class IdpInitiatedLoginController {

    private static final Logger log = LoggerFactory.getLogger(IdpInitiatedLoginController.class);

    private final IdpWebSsoProfile idpWebSsoProfile;
    private final MetadataManager metadataManager;
    private final SamlServiceProviderConfigurator configurator;
    private final SAMLContextProvider contextProvider;
    private final IdpSamlAuthenticationSuccessHandler idpSamlAuthenticationSuccessHandler;

    public IdpInitiatedLoginController(IdpWebSsoProfile idpWebSsoProfile,
                                       @Qualifier("idpMetadataManager") MetadataManager metadataManager,
                                       SamlServiceProviderConfigurator configurator,
                                       @Qualifier("idpContextProvider") SAMLContextProvider contextProvider,
                                       IdpSamlAuthenticationSuccessHandler idpSamlAuthenticationSuccessHandler) {
        this.idpWebSsoProfile = idpWebSsoProfile;
        this.metadataManager = metadataManager;
        this.configurator = configurator;
        this.contextProvider = contextProvider;
        this.idpSamlAuthenticationSuccessHandler = idpSamlAuthenticationSuccessHandler;
    }

    @RequestMapping("/saml/idp/initiate")
    public void initiate(@RequestParam(value = "sp", required = false) String sp,
                         HttpServletRequest request,
                         HttpServletResponse response) {

        if (!hasText(sp)) {
            throw new ProviderNotFoundException("Missing sp request parameter. sp parameter must be a valid and configured entity ID");
        }
        log.debug(String.format("IDP is initiating authentication request to SP[%s]", sp));
        Optional<SamlServiceProviderHolder> holder = configurator.getSamlServiceProviders().stream().filter(serviceProvider -> sp.equals(serviceProvider.getSamlServiceProvider().getEntityId())).findFirst();
        if (holder.isEmpty()) {
            log.debug(String.format("SP[%s] was not found, aborting saml response", sp));
            throw new ProviderNotFoundException("Invalid sp entity ID. sp parameter must be a valid and configured entity ID");
        }
        if (!holder.get().getSamlServiceProvider().isActive()) {
            log.debug(String.format("SP[%s] is disabled, aborting saml response", sp));
            throw new ProviderNotFoundException("Service provider is disabled.");
        }
        if (!holder.get().getSamlServiceProvider().getConfig().isEnableIdpInitiatedSso()) {
            log.debug(String.format("SP[%s] initiated login is disabled, aborting saml response", sp));
            throw new ProviderNotFoundException("IDP initiated login is disabled for this service provider.");
        }

        String nameId = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        try {
            String assertionLocation = getAssertionConsumerURL(sp);
            log.debug(String.format("IDP is sending assertion for SP[%s] to %s", sp, assertionLocation));
            AuthnRequest authnRequest = idpWebSsoProfile.buildIdpInitiatedAuthnRequest(nameId, sp, assertionLocation);
            SAMLMessageContext samlContext = getSamlContext(sp, authnRequest, request, response);
            idpWebSsoProfile.sendResponse(SecurityContextHolder.getContext().getAuthentication(),
                                          samlContext,
                                          getIdpIniatedOptions());
            log.debug(String.format("IDP initiated authentication and responded to SP[%s]", sp));
        } catch (MetadataProviderException |
            SAMLException |
            SecurityException |
            MessageEncodingException |
            MarshallingException |
            SignatureException e) {
            log.debug(String.format("IDP is unable to process assertion for SP[%s]", sp), e);
            throw new ProviderNotFoundException("Unable to process SAML assertion. Response not sent.");
        }
    }

    public String getAssertionConsumerURL(String sp) throws MetadataProviderException {
        EntityDescriptor entityDescriptor = metadataManager.getEntityDescriptor(sp);
        SPSSODescriptor spssoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        List<AssertionConsumerService> assertionConsumerServices = spssoDescriptor.getAssertionConsumerServices();
        Optional<AssertionConsumerService> defaultService = assertionConsumerServices.stream().filter(IndexedEndpoint::isDefault).findFirst();
        if (defaultService.isPresent()) {
            return defaultService.get().getLocation();
        } else {
            return assertionConsumerServices.get(0).getLocation();
        }
    }

    protected SAMLMessageContext getSamlContext(String spEntityId,
                                                AuthnRequest authnRequest,
                                                HttpServletRequest request,
                                                HttpServletResponse response) throws MetadataProviderException {
        SAMLMessageContext samlContext = contextProvider.getLocalAndPeerEntity(request, response);
        samlContext.setPeerEntityId(spEntityId);
        samlContext.setPeerEntityRole(new QName(SAMLConstants.SAML20MD_NS, DEFAULT_ELEMENT_LOCAL_NAME, "md"));
        idpSamlAuthenticationSuccessHandler.populatePeerContext(samlContext);
        samlContext.setInboundSAMLMessage(authnRequest);
        return samlContext;
    }

    protected IdpWebSSOProfileOptions getIdpIniatedOptions() {
        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        return options;
    }

    @ExceptionHandler
    public String handleException(AuthenticationException ae, HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(400);
        request.setAttribute("saml_error", ae.getMessage());
        return "external_auth_error";
    }
}
