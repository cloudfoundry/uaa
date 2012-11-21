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
package org.cloudfoundry.identity.uaa.audit.event;

import java.security.Principal;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;

/**
 * Base class for UAA events that want to publish audit records.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 * 
 */
public abstract class AbstractUaaEvent extends ApplicationEvent {

	protected AbstractUaaEvent(Object source) {
		super(source);
	}

	public void process(UaaAuditService auditor) {
		auditor.log(getAuditEvent());
	}

	protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin) {
		return new AuditEvent(type, principalId, origin, null, System.currentTimeMillis());
	}

	protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin, String data) {
		return new AuditEvent(type, principalId, origin, data, System.currentTimeMillis());
	}

	// Ideally we want to get to the point where details is never null, but this isn't currently possible
	// due to some OAuth authentication scenarios which don't set it.
	protected String getOrigin(Principal principal) {
		if (principal instanceof Authentication) {
			Authentication caller = (Authentication) principal;
			if (caller != null) {
				return "" + caller.getDetails();
			}
		}
		return principal == null ? null : principal.getName();
	}

	public abstract AuditEvent getAuditEvent();

}
