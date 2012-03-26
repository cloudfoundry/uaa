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

import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * Service interface which handles the different types of audit event raised by the system.
 */
public interface UaaAuditService {
	/**
	 * Authentication of a specific user, i.e. a person
	 */
	void userAuthenticationSuccess(UaaUser user, UaaAuthenticationDetails details);

	void userAuthenticationFailure(UaaUser user, UaaAuthenticationDetails details);

	void userNotFound(String name, UaaAuthenticationDetails details);

	/**
	 * Authentication of any other (non-user) principal.
	 */
//	void principalAuthenticationSuccess(String name);

	void principalAuthenticationFailure(String name, UaaAuthenticationDetails details);

	void principalNotFound(String name, UaaAuthenticationDetails details);

	List<AuditEvent> find(String principal, long after);
}
