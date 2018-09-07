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
import javax.servlet.http.HttpServletRequestWrapper;

import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultSessionAssertionStore;
import org.springframework.security.saml.validation.ValidationResult;

public class SamlIdpAuthenticationRequestFilter extends SamlIdpAuthenticationFilter {
    public SamlIdpAuthenticationRequestFilter(
        SamlProviderProvisioning<IdentityProviderService> samlProvisioning,
        DefaultSessionAssertionStore defaultSessionAssertionStore,
        SamlRequestMatcher requestMatcher,
        SamlServiceProviderProvisioning serviceProviderProvisioning,
        JdbcScimUserProvisioning scimUserProvisioning,
        SamlServiceProviderConfigurator samlServiceProviderConfigurator) {
        super(
            samlProvisioning,
            defaultSessionAssertionStore,
            requestMatcher,
            serviceProviderProvisioning,
            scimUserProvisioning,
            samlServiceProviderConfigurator
        );
    }

    @Override
    protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {

        IdentityProviderService provider = getProvisioning().getHostedProvider();
        String param = request.getParameter("SAMLRequest");
        AuthenticationRequest authn =
            provider.fromXml(
                param,
                true,
                HttpMethod.GET.name().equalsIgnoreCase(request.getMethod()),
                AuthenticationRequest.class
            );
        ValidationResult validationResult = provider.validate(authn);
        if (validationResult.hasErrors()) {
            throw new ProviderNotFoundException(
                "Unable to validate authentication request. "+validationResult.toString()
            );
        }
        ServiceProviderMetadata serviceProvider = provider.getRemoteProvider(authn);
        if (serviceProvider == null) {
            throw new ProviderNotFoundException("Unable to resolve a configured service provider from the authentication request");
        }
        final String spEntityId = serviceProvider.getEntityId();
        HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request) {
            @Override
            public String getParameter(String name) {
                if ("sp".equals(name)) {
                    return spEntityId;
                }
                return super.getParameter(name);
            }
        };

        return super.getTargetProvider(wrapper);
    }
}
