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
package org.cloudfoundry.identity.uaa.scim;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.beans.factory.InitializingBean;

/**
 * Convenience class for provisioning user accounts from {@link UaaUser} instances.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimUserBootstrap implements InitializingBean {

	private static final Log logger = LogFactory.getLog(ScimUserBootstrap.class);

	private final ScimUserProvisioning scimUserProvisioning;

	private final Collection<UaaUser> users;

	public ScimUserBootstrap(ScimUserProvisioning scimUserProvisioning) {
		this(scimUserProvisioning, Collections.<UaaUser> emptySet());
	}

	public ScimUserBootstrap(ScimUserProvisioning scimUserProvisioning, Collection<UaaUser> users) {
		this.scimUserProvisioning = scimUserProvisioning;
		this.users = Collections.unmodifiableCollection(users);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		for (UaaUser u : users) {
			addUser(u);
		}
	}

	/**
	 * Add a user account from the properties provided.
	 * 
	 * @param user a UaaUser
	 * @return the ScimUser added
	 */
	public ScimUser addUser(UaaUser user) {
		ScimUser scimUser = getScimUser(user);
		List<ScimUser> users = scimUserProvisioning.retrieveUsers("userName eq '" + user.getUsername() + "'");
		if (users.isEmpty()) {
			logger.info("Registering new user account: " + user);
			// TODO: send a message or raise an event that can be used to inform the user of his new password
			return scimUserProvisioning.createUser(scimUser, user.getPassword());
		}
		else {
			logger.debug("Not registering existing user: " + user);
			// We don't update existing accounts - use the ScimUserProvisioning for that
			return scimUser;
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
