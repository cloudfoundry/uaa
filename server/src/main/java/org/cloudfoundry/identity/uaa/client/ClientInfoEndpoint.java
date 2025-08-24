/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.Collections;

/**
 * Controller which allows clients to inspect their own registration data.
 *
 * @author Dave Syer
 */
@Controller
public class ClientInfoEndpoint {

    private final MultitenantClientServices clientDetailsService;
    private final IdentityZoneManager identityZoneManager;

    public ClientInfoEndpoint(
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final IdentityZoneManager identityZoneManager) {
        this.clientDetailsService = clientDetailsService;
        this.identityZoneManager = identityZoneManager;
    }

    @RequestMapping(value = "/clientinfo")
    @ResponseBody
    public ClientDetails clientinfo(Principal principal) {
        String clientId = principal.getName();
        UaaClientDetails client = new UaaClientDetails(clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId()));
        client.setClientSecret(null);
        client.setAdditionalInformation(Collections.<String, Object>emptyMap());
        return client;
    }
}
