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
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;

public interface UaaAuthenticationJsonBase {
    String DETAILS = "details";
    String PRINCIPAL = "principal";
    String AUTHORITIES = "authorities";
    String EXTERNAL_GROUPS = "externalGroups";
    String EXPIRES_AT = "expiresAt";
    String AUTH_TIME = "authenticatedTime";
    String AUTHENTICATED = "authenticated";
    String USER_ATTRIBUTES = "userAttributes";
    String AUTHENTICATION_METHODS = "authenticationMethods";
    String AUTHN_CONTEXT_CLASS_REF = "authContextClassRef";
    String PREVIOIUS_LOGIN_SUCCESS_TIME = "previousLoginSuccessTime";
    String IDP_ID_TOKEN = "idpIdToken";
    String NULL_STRING = "null";

    default Set<String> serializeAuthorites(Collection<? extends GrantedAuthority> authorities) {
        return UaaStringUtils.getStringsFromAuthorities(authorities);
    }

    default List<? extends GrantedAuthority> deserializeAuthorites(Collection<String> authorities) {
        return UaaStringUtils.getAuthoritiesFromStrings(authorities);
    }

}
