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

import java.security.Principal;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.oauth2.provider.ClientDetails;

/**
 * Service interface which handles the different types of audit event raised by the system.
 * 
 * @author Luke Talyor
 * @author Dave Syer
 */
public interface UaaAuditService {

	/**
	 * Authentication of a specific user, i.e. a person
	 */
	void userAuthenticationSuccess(UaaUser user, UaaAuthenticationDetails details);

	/**
	 * Authentication of a specific user, i.e. a person, failed
	 */
	void userAuthenticationFailure(UaaUser user, UaaAuthenticationDetails details);

	/**
	 * User was searched for by name and not found
	 */
	void userNotFound(String name, UaaAuthenticationDetails details);
	
	/**
	 * Password change succeeded
	 */
	void passwordChangeSuccess(String message, UaaUser user, Principal caller);

	/**
	 * Password change failed
	 */
	void passwordChangeFailure(String message, UaaUser user, Principal caller);

	/**
	 * Password change failed and no target user was found
	 */
	void passwordChangeFailure(String message, Principal caller);

	/**
	 * Secret change succeeded
	 */
	void secretChangeSuccess(String message, ClientDetails client, Principal caller);

	/**
	 * Secret change failed
	 */
	void secretChangeFailure(String message, ClientDetails client, Principal caller);

	/**
	 * Secret change failed and no target client was found
	 */
	void secretChangeFailure(String message, Principal caller);

	/**
	 * Authentication of any other (non-user) principal.
	 */
	void principalAuthenticationFailure(String name, UaaAuthenticationDetails details);

	/**
	 * Authentication of any other (non-user) principal failed.
	 */
	void principalNotFound(String name, UaaAuthenticationDetails details);

	/**
	 * Find audit events relating to the specified principal since the time provided.
	 * 
	 * @param principal the principal name to search for
	 * @param after epoch in milliseconds
	 * @return audit events relating to the principal
	 */
	List<AuditEvent> find(String principal, long after);

}
