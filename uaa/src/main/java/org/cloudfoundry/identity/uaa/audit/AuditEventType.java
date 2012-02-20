/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.audit;

/**
 * Allows audit events to be classified by type.
 *
 * @author Luke Taylor
 */
public enum AuditEventType {
	// Do not change the code values, as these are used in the database.
	UserAuthenticationSuccess (0),
	UserAuthenticationFailure (1),
	UserNotFound (2),
	PasswordChanged (3),
	PrincipalAuthenticationSuccess (4),
	PrincipalAuthenticationFailure (5),
	PrincipalNotFound (6);

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
