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
import java.util.List;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;

import static org.springframework.util.StringUtils.hasText;

public class SamlSpAuthenticationRequestFilter extends SamlAuthenticationRequestFilter {

    private final String defaultRelayState;
    public SamlSpAuthenticationRequestFilter(SamlProviderProvisioning<ServiceProviderService> provisioning,
                                             String relayState) {
        super(provisioning);
        this.defaultRelayState = relayState;
    }

    @Override
    protected IdentityProviderMetadata getIdentityProvider(ServiceProviderService provider, String idpIdentifier) {
        String alias = idpIdentifier;
        List<IdentityProviderMetadata> providers = provider.getRemoteProviders();
        for (IdentityProviderMetadata idp : providers) {
            if (alias.equals(idp.getEntityAlias())) {
                return idp;
            }
        }
        return super.getIdentityProvider(provider, idpIdentifier);
    }

    @Override
    protected String getRelayState(ServiceProviderService provider, HttpServletRequest request) {
        if (hasText(defaultRelayState)) {
            if (UaaUrlUtils.isUrl(defaultRelayState)) {
                return defaultRelayState;
            } else {
                if (IdentityZoneHolder.isUaa()) {
                    return defaultRelayState;
                } else {
                    return IdentityZoneHolder.get().getSubdomain() + "." + defaultRelayState;
                }
            }
        }
        return null;
    }
}
