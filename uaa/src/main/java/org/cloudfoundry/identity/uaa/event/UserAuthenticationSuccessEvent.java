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
package org.cloudfoundry.identity.uaa.event;

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class UserAuthenticationSuccessEvent extends AbstractUaaAuthenticationEvent {
	private final UaaUser user;

	public UserAuthenticationSuccessEvent(UaaUser user, Authentication authentication) {
		super(authentication);
		this.user = user;
	}

	@Override
	public void process(UaaAuditService auditor) {
		auditor.userAuthenticationSuccess(user, (UaaAuthenticationDetails) getAuthentication().getDetails());
	}
}
