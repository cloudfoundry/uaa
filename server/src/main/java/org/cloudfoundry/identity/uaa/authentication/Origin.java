/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.RemoteUserAuthentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;

public class Origin {

    public static String getUserId(Authentication authentication) {
        String id;
        if (authentication.getPrincipal() instanceof UaaPrincipal) {
            return ((UaaPrincipal) authentication.getPrincipal()).getId();
        } else if (authentication instanceof RemoteUserAuthentication remoteUserAuthentication) {
            return remoteUserAuthentication.getId();
        } else if (authentication instanceof UaaAuthentication uaaAuthentication) {
            return uaaAuthentication.getPrincipal().getId();
        } else if (authentication instanceof UsernamePasswordAuthenticationToken auth) {
            if (auth.getPrincipal() instanceof UaaPrincipal) {
                return ((UaaPrincipal) auth.getPrincipal()).getId();
            }
        } else if ((id = getUserIdThroughReflection(authentication, "getId")) != null) {
            return id;
        }
        throw new IllegalArgumentException("Can not handle authentication[" + authentication + "] of class:" + authentication.getClass());
    }

    public static String getUserIdThroughReflection(Authentication authentication, String methodName) {
        try {
            Method m = ReflectionUtils.findMethod(authentication.getClass(), methodName);
            if (m == null) {
                return null;
            }
            Object id = ReflectionUtils.invokeMethod(m, authentication);
            if (id != null) {
                return id.toString();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

}
