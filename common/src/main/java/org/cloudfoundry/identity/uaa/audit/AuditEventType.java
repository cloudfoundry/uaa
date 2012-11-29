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
 * Allows audit events to be classified by type.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public enum AuditEventType {

	// Do not change the code values, as these are used in the database.
	UserAuthenticationSuccess (0),
	UserAuthenticationFailure (1),
	UserNotFound (2),
	PasswordChangeSuccess (3),
	PrincipalAuthenticationSuccess (4),
	PrincipalAuthenticationFailure (5),
	PrincipalNotFound (6),
	PasswordChangeFailure (7),
	SecretChangeSuccess (8),
	SecretChangeFailure (9),
	ClientCreateSuccess (10),
	ClientUpdateSuccess (11),
	ClientDeleteSuccess (12);

	private final int code;

	private AuditEventType(int code) {
		this.code = code;
	}

	public static AuditEventType fromCode(int code) {
		for(AuditEventType a : AuditEventType.values()) {
			if (a.getCode() == code) {
				return a;
			}
		}
		throw new IllegalArgumentException("No event type with code " + code + " exists");
	}

	public int getCode() {
		return code;
	}
}
