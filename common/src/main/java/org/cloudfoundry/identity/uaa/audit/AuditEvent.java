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
package org.cloudfoundry.identity.uaa.audit;

/**
 * Used when retrieving audit data from the audit service
 */
public class AuditEvent {

	private final AuditEventType type;
	private final String principalId;
	private final String origin;
	private final long time;
	private final String data;

	public AuditEvent(AuditEventType type, String principalId, String origin, String data, long time) {
		this.type = type;
		this.data = data;
		this.origin = origin;
		this.time = time;
		this.principalId = principalId;
	}

	public AuditEventType getType() {
		return type;
	}

	public String getPrincipalId() {
		return principalId;
	}

	public String getOrigin() {
		return origin;
	}

	public long getTime() {
		return time;
	}

	public String getData() {
		return data;
	}
}
