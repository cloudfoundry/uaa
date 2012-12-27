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

package org.cloudfoundry.identity.uaa.scim.endpoints;

import java.util.List;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Convenience aspect for converting user ids to user names (or vice versa) and injecting the result into the
 * intercepted method call. Using this makes the conversion transparent to callers but it only makes sense where the
 * SCIM features are available (i.e. the UAA controls its own user accounts).
 * 
 * @author Dave Syer
 * 
 */
public class UserIdInjector implements MethodInterceptor, InitializingBean {
	
	public static enum Mode {
		ID_TO_NAME,
		NAME_TO_ID
	}

	private ScimUserProvisioning scimUserProvisioning;

	private int inputIndex = 0;

	private Mode mode = Mode.ID_TO_NAME;

	boolean lookup = false;
	
	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.state(scimUserProvisioning!=null, "ScimUserProvisioning must be provided");
	}
	
	/**
	 * @param inputIndex the index of the incoming args that may need to be converted
	 */
	public void setInputIndex(int inputIndex) {
		this.inputIndex = inputIndex;
	}
	
	/**
	 * @param scimUserProvisioning the scimUserProvisioning to set
	 */
	public void setScimUserProvisioning(ScimUserProvisioning scimUserProvisioning) {
		this.scimUserProvisioning = scimUserProvisioning;
	}

	/**
	 * @param lookup the flag to set
	 */
	public void setLookup(boolean lookup) {
		this.lookup = lookup;
	}

	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		Object[] args = invocation.getArguments();
		if (!lookup || !(args[inputIndex] instanceof String)) {
			return invocation.proceed();
		}
		String result = (String) args[inputIndex];
		if (mode  == Mode.NAME_TO_ID) {
			result = getUserId(result);
		} else {
			result = getUserName(result);			
		}
		args[inputIndex] = result;
		return invocation.proceed();
	}

	private String getUserName(String userId) {
		String userName = userId;
		try {
			// If the request came in for a user by id we should be able to retrieve the userName
			ScimUser scimUser = scimUserProvisioning.retrieve(userName);
			if (scimUser != null) {
				userName = scimUser.getUserName();
			}
		}
		catch (ScimResourceNotFoundException e) {
			// ignore
		}
		return userName;
	}

	private String getUserId(String userName) {
		String userId = userName;
		List<ScimUser> users = scimUserProvisioning.query("userName eq '" + userName + "'");
		if (!users.isEmpty()) {
			// Assume the userName is unique
			userId = users.get(0).getId();
		}
		return userId;
	}

}
