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

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataManager;

import javax.xml.namespace.QName;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensaml.common.xml.SAMLConstants.SAML20P_NS;

public class IdpInitiatedLoginControllerTests {

    private SamlServiceProviderConfigurator configurator;
    private SAMLContextProvider contextProvider;
    private MetadataManager metadataManager;
    private IdpSamlAuthenticationSuccessHandler idpSamlAuthenticationSuccessHandler;
    private UaaAuthentication authentication;

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private IdpInitiatedLoginController controller;
    private IdpWebSsoProfile webSsoProfile;

    @Before
    public void setUp() {
        configurator = mock(SamlServiceProviderConfigurator.class);
        contextProvider = mock(SAMLContextProvider.class);
        metadataManager = mock(MetadataManager.class);
        idpSamlAuthenticationSuccessHandler = mock(IdpSamlAuthenticationSuccessHandler.class);
        webSsoProfile = mock(IdpWebSsoProfile.class);
        authentication = mock(UaaAuthentication.class);

        controller = spy(new IdpInitiatedLoginController(webSsoProfile,
                metadataManager, configurator, contextProvider, idpSamlAuthenticationSuccessHandler));

        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void missing_sp_parameter() {
        exception.expect(ProviderNotFoundException.class);
        exception.expectMessage("Missing sp request parameter.");
        controller.initiate(null, request, response);
    }

    @Test
    public void invalid_sp_parameter() {
        exception.expect(ProviderNotFoundException.class);
        exception.expectMessage("Invalid sp entity ID.");
        request.setParameter("sp", "invalid");
        when(configurator.getSamlServiceProviders()).thenReturn(Collections.emptyList());
        controller.initiate("invalid", request, response);
    }

    @Test
    public void feature_disabled() throws Exception {
        exception.expect(ProviderNotFoundException.class);
        exception.expectMessage("IDP initiated login is disabled for this service provider.");
        String entityID = "validEntityID";
        setupForIdpInitiatedLogin(entityID, false);
        controller.initiate(entityID, request, response);
    }

    @Test
    public void metadata_error() throws Exception {
        exception.expect(ProviderNotFoundException.class);
        exception.expectMessage("Unable to process SAML assertion.");
        when(metadataManager.getEntityDescriptor(anyString())).thenThrow(new MetadataProviderException("any message"));
        String entityID = "validEntityID";
        SamlServiceProvider provider = new SamlServiceProvider();
        provider.setConfig(new SamlServiceProviderDefinition());
        provider.getConfig().setEnableIdpInitiatedSso(true);
        provider.setActive(true);
        provider.setEntityId(entityID);
        SamlServiceProviderHolder holder = new SamlServiceProviderHolder(null, provider);
        when(configurator.getSamlServiceProviders()).thenReturn(Collections.singletonList(holder));
        controller.initiate(entityID, request, response);
    }

    @Test
    public void disabled_provider() {
        exception.expect(ProviderNotFoundException.class);
        exception.expectMessage("Service provider is disabled.");
        String entityID = "validEntityID";
        SamlServiceProvider provider = new SamlServiceProvider();
        provider.setEntityId(entityID);
        provider.setActive(false);
        SamlServiceProviderHolder holder = new SamlServiceProviderHolder(null, provider);
        when(configurator.getSamlServiceProviders()).thenReturn(Collections.singletonList(holder));
        controller.initiate(entityID, request, response);
    }



    @Test
    public void happy_path() throws Exception {
        String entityID = "validEntityID";
        SAMLMessageContext samlMessageContext = setupForIdpInitiatedLogin(entityID, true);

        controller.initiate(entityID, request, response);

        verify(webSsoProfile).sendResponse(
            same(authentication),
            same(samlMessageContext),
            any()
        );
    }

    public SAMLMessageContext setupForIdpInitiatedLogin(String entityID, boolean enableIdpInitiatedSso) throws MetadataProviderException {
        String responseUrl = "http://sso.response.com/url";
        String nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        AuthnRequest authnRequest = mock(AuthnRequest.class);

        SamlServiceProvider provider = new SamlServiceProvider();
        provider.setActive(true);
        provider.setEntityId(entityID);
        provider.setConfig(new SamlServiceProviderDefinition());
        provider.getConfig().setEnableIdpInitiatedSso(enableIdpInitiatedSso);
        SamlServiceProviderHolder holder = new SamlServiceProviderHolder(null, provider);

        doReturn(responseUrl).when(controller).getAssertionConsumerURL(anyString());
        when(configurator.getSamlServiceProviders()).thenReturn(Collections.singletonList(holder));


        when(webSsoProfile.buildIdpInitiatedAuthnRequest(
            eq(nameIdFormat),
            eq(entityID),
            eq(responseUrl)
        )).thenReturn(authnRequest);

        SAMLMessageContext samlMessageContext = mock(SAMLMessageContext.class);
        doReturn(samlMessageContext)
            .when(controller)
            .getSamlContext(
                eq(entityID),
                same(authnRequest),
                same(request),
                same(response)
            );
        return samlMessageContext;
    }

    @Test
    public void get_saml_message_context() throws Exception {
        String entityID = "validEntityID";
        SAMLMessageContext context = mock(SAMLMessageContext.class);
        when(contextProvider.getLocalAndPeerEntity(same(request), same(response))).thenReturn(
            context
        );
        controller.getSamlContext(entityID, mock(AuthnRequest.class), request, response);
        verify(context, times(1)).setPeerEntityId(entityID);
        ArgumentCaptor<QName> qNameCaptor = ArgumentCaptor.forClass(QName.class);
        verify(context, times(1)).setPeerEntityRole(qNameCaptor.capture());
        assertNotNull(qNameCaptor.getValue());
        assertEquals(SAMLConstants.SAML20MD_NS, qNameCaptor.getValue().getNamespaceURI());
        assertEquals(SPSSODescriptor.DEFAULT_ELEMENT_LOCAL_NAME, qNameCaptor.getValue().getLocalPart());
    }

    @Test
    public void handle_exception() {
        String view = controller.handleException(new ProviderNotFoundException("message"), request, response);
        assertEquals(400, response.getStatus());
        assertEquals("message", request.getAttribute("saml_error"));
        assertEquals("external_auth_error", view);
    }

    @Test
    public void get_assertion_consumer_service_url() throws Exception {
        String entityID = "validEntityID";
        EntityDescriptor entityDescriptor = mock(EntityDescriptor.class);
        when(metadataManager.getEntityDescriptor(eq(entityID))).thenReturn(entityDescriptor);
        SPSSODescriptor spssoDescriptor = mock(SPSSODescriptor.class);
        when(entityDescriptor.getSPSSODescriptor(eq(SAML20P_NS))).thenReturn(spssoDescriptor);
        AssertionConsumerService service = mock(AssertionConsumerService.class);
        when(service.getLocation()).thenReturn("service-location");
        when(service.isDefault()).thenReturn(false);
        AssertionConsumerService defaultService = mock(AssertionConsumerService.class);
        when(defaultService.getLocation()).thenReturn("default-location");
        when(defaultService.isDefault()).thenReturn(true);

        when(spssoDescriptor.getAssertionConsumerServices()).thenReturn(Arrays.asList(service, defaultService));
        String url = controller.getAssertionConsumerURL(entityID);
        assertEquals("default-location", url);
        when(defaultService.isDefault()).thenReturn(false);
        url = controller.getAssertionConsumerURL(entityID);
        assertEquals("service-location", url);
    }



}