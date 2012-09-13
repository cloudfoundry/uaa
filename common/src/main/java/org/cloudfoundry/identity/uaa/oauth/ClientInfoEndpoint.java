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

import java.security.Principal;
import java.util.Collections;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller which allows clients to inspect their own registration data.
 * 
 * @author Dave Syer
 */
@Controller
public class ClientInfoEndpoint implements InitializingBean {

	private ClientDetailsService clientDetailsService;

	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(clientDetailsService, "clientDetailsService must be set");
	}

	@RequestMapping(value = "/clientinfo")
	@ResponseBody
	public ClientDetails clientinfo(Principal principal) {

		String clientId = principal.getName();
		BaseClientDetails client = new BaseClientDetails(clientDetailsService.loadClientByClientId(clientId));
		client.setClientSecret(null);
		client.setAdditionalInformation(Collections.<String, Object> emptyMap());
		return client;

	}

}
