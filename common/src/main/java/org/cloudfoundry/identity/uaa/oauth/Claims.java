/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

/**
 * <p>
 * Constants that can be used to work with claims from OAuth2 Bearer and OpenID
 * Connect tokens
 * </p>
 *
 * @author Joel D'sa
 * @author Dave Syer
 *
 */
public class Claims {
    public static final String USER_ID = "user_id";
    public static final String USER_NAME = "user_name";
    public static final String NAME = "name";
    public static final String GIVEN_NAME = "given_name";
    public static final String FAMILY_NAME = "family_name";
    public static final String EMAIL = "email";
    public static final String CLIENT_ID = "client_id";
    public static final String EXP = "exp";
    public static final String AUTHORITIES = "authorities";
    public static final String SCOPE = "scope";
    public static final String JTI = "jti";
    public static final String AUD = "aud";
    public static final String SUB = "sub";
    public static final String ISS = "iss";
    public static final String IAT = "iat";
    public static final String CID = "cid";
    public static final String GRANT_TYPE = "grant_type";
    public static final String ADDITIONAL_AZ_ATTR = "az_attr";
    public static final String AZP = "azp";
    public static final String AUTH_TIME = "auth_time";
    public static final String ZONE_ID = "zid";
    public static final String REVOCATION_SIGNATURE = "rev_sig";
}
