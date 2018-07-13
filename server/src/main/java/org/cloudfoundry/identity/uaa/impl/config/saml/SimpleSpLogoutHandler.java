/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.impl.config.saml;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class SimpleSpLogoutHandler implements LogoutHandler {

    private final SamlProviderProvisioning<ServiceProviderService> resolver;
    private final SamlTransformer transformer;

    public SimpleSpLogoutHandler(SamlProviderProvisioning<ServiceProviderService> resolver, SamlTransformer transformer) {
        this.resolver = resolver;
        this.transformer = transformer;
    }

    public SamlProviderProvisioning<ServiceProviderService> getResolver() {
        return resolver;
    }

    public SamlTransformer getTransformer() {
        return transformer;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null && authentication.getCredentials() instanceof SamlAuthentication) {
            try {
                logoutSpInitiated(
                    request,
                    response,
                    (SamlAuthentication) authentication.getCredentials()
                );
            } catch (IOException e) {
                throw new SamlException(e);
            }
        }
    }

    protected boolean logoutSpInitiated(HttpServletRequest request,
                                        HttpServletResponse response,
                                        SamlAuthentication sa) throws IOException {
        ServiceProviderService provider = getResolver().getHostedProvider();
        ServiceProviderMetadata sp = provider.getMetadata();
        IdentityProviderMetadata idp = provider.getRemoteProvider(sa.getAssertingEntityId());
        LogoutRequest lr = provider.logoutRequest(
            idp,
            (NameIdPrincipal) sa.getSamlPrincipal()
        );
        if (lr.getDestination() != null) {
            String redirect = getRedirectUrl(lr, lr.getDestination().getLocation(), "SAMLRequest");
            response.sendRedirect(redirect);
            return true;
        }
        return false;
    }

    protected String getRedirectUrl(Saml2Object lr, String location, String paramName)
        throws UnsupportedEncodingException {
        String xml = getTransformer().toXml(lr);
        String value = getTransformer().samlEncode(xml, true);
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(location);
        return builder.queryParam(paramName, UriUtils.encode(value, StandardCharsets.UTF_8.name()))
            .build()
            .toUriString();
    }
}
