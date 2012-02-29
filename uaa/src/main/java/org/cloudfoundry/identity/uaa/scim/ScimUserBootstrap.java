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
package org.cloudfoundry.identity.uaa.scim;

import java.util.Collection;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.beans.factory.InitializingBean;

/**
 * In-memory user account information storage.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimUserBootstrap implements InitializingBean {

	private final ScimUserProvisioning scimUserProvisioning;

	private final Collection<UaaUser> users;

	public ScimUserBootstrap(ScimUserProvisioning scimUserProvisioning, Collection<UaaUser> users) {
		this.scimUserProvisioning = scimUserProvisioning;
		this.users = users;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		for (UaaUser u : users) {
			scimUserProvisioning.createUser(getScimUser(u), u.getPassword());
		}
	}

	/**
	 * Convert UaaUser to SCIM data.
	 */
	private ScimUser getScimUser(UaaUser user) {
		ScimUser scim = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
		scim.addEmail(user.getEmail());
		return scim;
	}
}
