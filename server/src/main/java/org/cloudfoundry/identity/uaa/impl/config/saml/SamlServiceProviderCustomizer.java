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

import java.util.LinkedList;
import java.util.List;

import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlServiceProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;

import static java.util.Arrays.asList;

public class SamlServiceProviderCustomizer extends HostBasedSamlServiceProviderProvisioning {
    public SamlServiceProviderCustomizer(SamlConfigurationRepository configuration, SamlTransformer transformer, SamlValidator validator, SamlMetadataCache cache) {
        super(configuration, transformer, validator, cache);
    }

    @Override
    public ServiceProviderService getHostedProvider() {
        ServiceProviderService result = super.getHostedProvider();
        customizeLogoutEndpoints(result);
        customizeEntityDescriptorId(result);
        customizeNameIdFormats(result);
        customizeAssertionConsumerService(result);
        customizeAttributeConsumerService(result);
        return result;
    }

    private void customizeAttributeConsumerService(ServiceProviderService result) {

    }

    private void customizeAssertionConsumerService(ServiceProviderService result) {
        List<Endpoint> acs = new LinkedList<>(result.getMetadata().getServiceProvider().getAssertionConsumerService());
        acs.removeIf(
            e -> e.getBinding() == Binding.REDIRECT
        );
        acs.add(
            new Endpoint()
                .setIndex(acs.size())
                .setLocation(acs.get(0).getLocation().replace("saml/SSO/alias/","oauth/token/alias/"))
                .setDefault(false)
                .setBinding(Binding.URI)
        );
        result.getMetadata().getServiceProvider().setAssertionConsumerService(acs);

    }

    private void customizeNameIdFormats(ServiceProviderService result) {
        result.getMetadata().getServiceProvider().setNameIds(
            asList(
                NameId.EMAIL,
                NameId.TRANSIENT,
                NameId.PERSISTENT,
                NameId.UNSPECIFIED,
                NameId.X509_SUBJECT
            )
        );
    }

    private void customizeEntityDescriptorId(ServiceProviderService result) {
        result.getMetadata().getServiceProvider().setId(result.getMetadata().getEntityAlias());
        result.getMetadata().setId(result.getMetadata().getEntityAlias());
    }

    private void customizeLogoutEndpoints(ServiceProviderService result) {
        List<Endpoint> existing = result.getMetadata().getServiceProvider().getSingleLogoutService();
        List<Endpoint> logoutService = new LinkedList<>();
        for (Endpoint endpoint : existing) {
            endpoint.setLocation(
                endpoint.getLocation().replace("saml/logout/alias", "saml/SingleLogout/alias")
            );
            logoutService.add(new Endpoint()
                .setLocation(endpoint.getLocation())
                .setIndex(logoutService.size())
                .setBinding(Binding.POST)
                .setDefault(false)
                .setResponseLocation(endpoint.getResponseLocation())
            );
            logoutService.add(
                endpoint
                    .setIndex(logoutService.size())
                    .setDefault(true)
            );


        }
        result.getMetadata().getServiceProvider().setSingleLogoutService(logoutService);
    }


}
