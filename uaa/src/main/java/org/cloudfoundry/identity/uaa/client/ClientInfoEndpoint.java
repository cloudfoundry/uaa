/*******************************************************************************
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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
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
public class ClientInfoEndpoint implements InitializingBean {

    private MultitenantClientServices clientDetailsService;

    /**
     * @param clientDetailsService the clientDetailsService to set
     */
    public void setClientDetailsService(MultitenantClientServices clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(clientDetailsService, "clientDetailsService must be set");
    }

    @RequestMapping(value = "/clientinfo")
    @ResponseBody
    public ClientDetails clientinfo(Principal principal) {

        String clientId = principal.getName();
        BaseClientDetails client = new BaseClientDetails(clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId()));
        client.setClientSecret(null);
        client.setAdditionalInformation(Collections.<String, Object> emptyMap());
        return client;

    }

}
