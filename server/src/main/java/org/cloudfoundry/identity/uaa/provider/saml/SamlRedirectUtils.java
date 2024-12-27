/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.web.util.UriComponentsBuilder;

public final class SamlRedirectUtils {

    private SamlRedirectUtils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static String getIdpRedirectUrl(SamlIdentityProviderDefinition definition) {
        String entityIdAlias = definition.getIdpEntityAlias();
        UriComponentsBuilder builder = UriComponentsBuilder.fromPath("saml2/authenticate/%s".formatted(entityIdAlias));
        return builder.build().toUriString();
    }

    public static String getZonifiedEntityId(String entityID, IdentityZone identityZone) {
        try {
            if (!identityZone.isUaa()) {
                String url = identityZone.getConfig().getSamlConfig().getEntityID();
                if (url != null) {
                    return url;
                }
            }
        } catch (Exception ignored) {
            // ignore
        }

        if (UaaUrlUtils.isUrl(entityID)) {
            return UaaUrlUtils.addSubdomainToUrl(entityID, identityZone.getSubdomain());
        } else {
            return UaaUrlUtils.getSubdomain(identityZone.getSubdomain()) + entityID;
        }
    }
}
