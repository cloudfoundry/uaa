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

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.JdbcClientDetailsService;

/**
 * @author Dave Syer
 *
 */
public class JitClientDetailsService extends JdbcQueryableClientDetailsService {

	public JitClientDetailsService(JdbcClientDetailsService delegate, JdbcTemplate jdbcTemplate) {
		super(delegate, jdbcTemplate);
	}

	@Override
	public ClientDetails retrieve(String clientId) throws OAuth2Exception {
		ClientDetails result;
		try {
			result = super.retrieve(clientId);
		} catch (OAuth2Exception e) {
			BaseClientDetails details = new BaseClientDetails(clientId, "openid", "openid", "authorization_code", UaaAuthority.UAA_NONE.toString());
			result = details;
		}
		return result;
	}

}
