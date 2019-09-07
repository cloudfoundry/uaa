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
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;

/**
 * This authentication provider attaches the SAMLMessageContext to an existing UaaAuthentication.
 */
public class IdpSamlAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        UaaAuthentication uaaAuthentication = (UaaAuthentication) securityContext.getAuthentication();
        SAMLMessageContext samlMessageContext = ((SAMLAuthenticationToken) authentication).getCredentials();
        uaaAuthentication.setSamlMessageContext(samlMessageContext);
        return uaaAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SAMLAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
