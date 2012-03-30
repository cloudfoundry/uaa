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

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.security.core.Authentication;

/**
 * Event which indicates that someone tried to authenticate as a non-existent user.
 * 
 * @author Luke Taylor
 */
public class UserNotFoundEvent extends AbstractUaaAuthenticationEvent {

	public UserNotFoundEvent(Authentication authentication) {
		super(authentication);
	}

	@Override
	public void process(UaaAuditService auditor) {
		auditor.userNotFound(getAuthentication().getName(), (UaaAuthenticationDetails) getAuthentication().getDetails());
	}
}
