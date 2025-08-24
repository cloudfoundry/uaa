/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.constants;

public final class OriginKeys {

    private OriginKeys() {
    }

    public static final String ORIGIN = "origin";
    public static final String UAA = "uaa";
    public static final String LOGIN_SERVER = "login-server";
    public static final String LDAP = "ldap";
    public static final String KEYSTONE = "keystone";
    public static final String SAML = "saml";
    public static final String OAUTH20 = "oauth2.0";
    public static final String OIDC10 = "oidc1.0";
    public static final String NotANumber = "NaN";
    public static final String UNKNOWN = "unknown";
}
