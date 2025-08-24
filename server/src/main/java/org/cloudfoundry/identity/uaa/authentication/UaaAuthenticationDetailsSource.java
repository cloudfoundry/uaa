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
package org.cloudfoundry.identity.uaa.authentication;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

/**
 * @author Luke Taylor
 */
@Component
public class UaaAuthenticationDetailsSource implements
        AuthenticationDetailsSource<HttpServletRequest, UaaAuthenticationDetails> {
    @Override
    public UaaAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new UaaAuthenticationDetails(context);
    }
}
