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
 *
 */
public enum Claims {
	USER_ID, USER_NAME, NAME, GIVEN_NAME, FAMILY_NAME, EMAIL, CLIENT_ID, EXP, AUTHORITIES, SCOPE, JTI, AUD, SUB, ISS, IAT, CID;

	public String value() {
		return this.name().toLowerCase();
	}
}
