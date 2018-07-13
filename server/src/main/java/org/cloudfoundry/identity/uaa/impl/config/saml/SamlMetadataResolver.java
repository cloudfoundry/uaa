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

import java.util.List;

import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

public class SamlMetadataResolver  {

    public ServiceProviderMetadata getLocalServiceProvider(String baseUrl) {
        ServiceProviderMetadata metadata = null; //TODO
        List<Endpoint> logoutService = metadata.getServiceProvider().getSingleLogoutService();
        if (!logoutService.isEmpty()) {
            for (Endpoint endpoint : logoutService) {
                endpoint.setLocation(
                    endpoint.getLocation().replace("saml/logout/alias", "saml/SingleLogout/alias")
                );
            }
        }
        return metadata;
    }
}
