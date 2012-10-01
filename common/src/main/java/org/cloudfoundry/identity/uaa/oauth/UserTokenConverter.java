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

import java.util.Map;

import org.springframework.security.core.Authentication;

/**
 * @author Dave Syer
 * 
 */
public interface UserTokenConverter {

	/**
	 * Extract information about the user to be used in an access token (i.e. for resource servers).
	 * 
	 * @param userAuthentication an authentication representing a user
	 * @return a map of key values representing the unique information about the user
	 */
	Map<String, ?> convertUserAuthentication(Authentication userAuthentication);

}
