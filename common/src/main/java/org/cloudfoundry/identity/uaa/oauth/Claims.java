/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth;

/**
 * <p>
 * Constants that can be used to work with claims from OAuth2 Bearer and OpenID Connect tokens
 * </p>
 *
 * @author Joel D'sa
 * @author Dave Syer
 *
 */
public class Claims {
	public static String USER_ID = "user_id";
	public static String USER_NAME = "user_name";
	public static String NAME = "name";
	public static String GIVEN_NAME = "given_name";
	public static String FAMILY_NAME = "family_name";
	public static String EMAIL = "email";
	public static String CLIENT_ID = "client_id";
	public static String EXP = "exp";
	public static String AUTHORITIES = "authorities";
	public static String SCOPE = "scope";
	public static String JTI = "jti";
	public static String AUD = "aud";
	public static String SUB = "sub";
	public static String ISS = "iss";
	public static String IAT = "iat";
	public static String CID = "cid";
	public static String GRANT_TYPE = "grant_type";
}
