/**
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

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 *
 */
public interface AccessTokenConverter {

	/**
	 * @param token an access token
	 * @param authentication the current OAuth authentication
	 * 
	 * @return a map representation of the token suitable for a JSON response
	 * 
	 */
	public abstract Map<String, Object> convertAccessToken(OAuth2AccessToken token,	OAuth2Authentication authentication);

}