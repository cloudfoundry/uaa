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
package org.cloudfoundry.identity.uaa.password.event;

import java.security.Principal;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * @author Dave Syer
 */
abstract class AbstractPasswordChangeEvent extends AbstractUaaEvent {

	private UaaUser user;

	private Principal principal;

	private String message;

	public AbstractPasswordChangeEvent(String message, UaaUser user, Principal principal) {
		super(principal);
		this.message = message;
		this.user = user;
		this.principal = principal;
	}

	UaaUser getUser() {
		return user;
	}

	Principal getPrincipal() {
		return principal;
	}

	String getMessage() {
		return message;
	}

}
