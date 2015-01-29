/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/identity-providers")
@RestController
public class IdentityProviderEndpoints {

    private final IdentityProviderProvisioning identityProviderProvisioning;

    public IdentityProviderEndpoints(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @RequestMapping(method = RequestMethod.POST)
    public ResponseEntity<IdentityProvider> createIdentityProvider(@RequestBody IdentityProvider body) {

        IdentityProvider createdIdp = identityProviderProvisioning.create(body);
        return new ResponseEntity<>(createdIdp, HttpStatus.CREATED);
    }
}
