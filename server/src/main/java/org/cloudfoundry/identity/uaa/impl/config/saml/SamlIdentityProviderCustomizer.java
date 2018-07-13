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
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlIdentityProviderProvisioning;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static java.util.Arrays.asList;

public class SamlIdentityProviderCustomizer extends HostBasedSamlIdentityProviderProvisioning {

    public SamlIdentityProviderCustomizer(SamlConfigurationRepository configuration, SamlTransformer transformer, SamlValidator validator, SamlMetadataCache cache) {
        super(configuration, transformer, validator, cache);
    }

    @Override
    public IdentityProviderService getHostedProvider() {
        IdentityProviderService result = super.getHostedProvider();
        customizeLogoutEndpoints(result);
        customizeSigning(result);
        customizeEntityDescriptorId(result);
        customizeNameIdFormats(result);
        customizeAttributeConsumerService(result);
        return result;
    }

    private void customizeAttributeConsumerService(IdentityProviderService result) {

    }

    private void customizeNameIdFormats(IdentityProviderService result) {
        result.getMetadata().getIdentityProvider().setNameIds(
            asList(
                NameId.EMAIL,
                NameId.PERSISTENT,
                NameId.UNSPECIFIED
            )
        );
    }

    private void customizeSigning(IdentityProviderService result) {
        result.getMetadata().setSigningKey(
            new SimpleKey(
                result.getMetadata().getSigningKey().getName(),
                result.getMetadata().getSigningKey().getPrivateKey(),
                result.getMetadata().getSigningKey().getCertificate(),
                result.getMetadata().getSigningKey().getPassphrase(),
                result.getMetadata().getSigningKey().getType()
            ),
            AlgorithmMethod.RSA_SHA1,
            DigestMethod.SHA1
        );
    }

    private void customizeEntityDescriptorId(IdentityProviderService result) {
        result.getMetadata().getIdentityProvider().setId(result.getMetadata().getEntityAlias());
        result.getMetadata().setId(result.getMetadata().getEntityAlias());
    }

    private void customizeLogoutEndpoints(IdentityProviderService result) {
        List<Endpoint> existing = result.getMetadata().getIdentityProvider().getSingleLogoutService();
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
        result.getMetadata().getIdentityProvider().setSingleLogoutService(logoutService);
    }


}
