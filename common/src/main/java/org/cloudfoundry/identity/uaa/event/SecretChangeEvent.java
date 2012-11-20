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

package org.cloudfoundry.identity.uaa.event;

import java.security.Principal;

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * @author Dave Syer
 *
 */
public class SecretChangeEvent extends AbstractUaaEvent {

	private Principal principal;
	private String message;
	private ClientDetails client;

	public SecretChangeEvent(String message, ClientDetails client, Principal principal) {
		super(principal);
		this.message = message;
		this.client = client;
		this.principal = principal;
	}

	@Override
	public void process(UaaAuditService auditor) {
		auditor.secretChangeSuccess(message, client, principal);
	}

}
