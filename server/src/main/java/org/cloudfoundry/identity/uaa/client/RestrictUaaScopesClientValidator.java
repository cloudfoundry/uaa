/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.client;


import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.springframework.security.core.GrantedAuthority;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

public class RestrictUaaScopesClientValidator implements ClientDetailsValidator {
    private final UaaScopes uaaScopes;

    public RestrictUaaScopesClientValidator(UaaScopes uaaScopes) {
        this.uaaScopes = uaaScopes;
    }

    public UaaScopes getUaaScopes() {
        return uaaScopes;
    }

    @Override
    public ClientSecretValidator getClientSecretValidator() {
        return null;
    }

    @Override
    public ClientDetails validate(ClientDetails clientDetails, Mode mode) throws InvalidClientDetailsException {
        if (Mode.CREATE.equals(mode) || Mode.MODIFY.equals(mode)) {
            for (String scope : clientDetails.getScope()) {
                if (uaaScopes.isUaaScope(scope)) {
                    throw new InvalidClientDetailsException(scope + " is a restricted scope.");
                }
            }
            for (GrantedAuthority authority : clientDetails.getAuthorities()) {
                if (uaaScopes.isUaaScope(authority)) {
                    throw new InvalidClientDetailsException(authority.getAuthority() + " is a restricted authority.");
                }
            }
        }
        return clientDetails;
    }
}
