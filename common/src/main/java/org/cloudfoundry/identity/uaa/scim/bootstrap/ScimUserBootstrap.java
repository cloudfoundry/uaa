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
package org.cloudfoundry.identity.uaa.scim.bootstrap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

/**
 * Convenience class for provisioning user accounts from {@link UaaUser} instances.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimUserBootstrap implements InitializingBean, ApplicationListener<NewUserAuthenticatedEvent> {

	private static final Log logger = LogFactory.getLog(ScimUserBootstrap.class);

	private final ScimUserProvisioning scimUserProvisioning;

	private final ScimGroupProvisioning scimGroupProvisioning;

	private final ScimGroupMembershipManager membershipManager;

	private boolean override = false;

	private final Collection<UaaUser> users;

	public ScimUserBootstrap(ScimUserProvisioning scimUserProvisioning, ScimGroupProvisioning scimGroupProvisioning, ScimGroupMembershipManager membershipManager) {
		this(scimUserProvisioning, scimGroupProvisioning, membershipManager, Collections.<UaaUser>emptySet());
	}

	/**
	 * Flag to indicate that user accounts can be updated as well as created.
	 *
	 * @param override the override flag to set (default false)
	 */
	public void setOverride(boolean override) {
		this.override = override;
	}

	public ScimUserBootstrap(ScimUserProvisioning scimUserProvisioning, ScimGroupProvisioning scimGroupProvisioning, ScimGroupMembershipManager membershipManager, Collection<UaaUser> users) {
		this.scimUserProvisioning = scimUserProvisioning;
		this.scimGroupProvisioning = scimGroupProvisioning;
		this.membershipManager = membershipManager;
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
		List<String> groupsToAddUser = new ArrayList<String>();
		for (ScimUser.Group g : getGroups(user.getAuthorities())) {
			groupsToAddUser.add(g.getDisplay());
		}
		List<ScimUser> users = scimUserProvisioning.query("userName eq '" + user.getUsername() + "'");
		if (users.isEmpty()) {
			logger.info("Registering new user account: " + user);
			// TODO: send a message or raise an event that can be used to inform the user of his new password
			scimUser = scimUserProvisioning.createUser(scimUser, user.getPassword());
		} else {
			if (!override) {
				logger.debug("Not registering existing user: " + user);
				// We don't update existing accounts - use the ScimUserProvisioning for that
				return scimUser;
			} else {
				logger.info("Updating user account: " + user);
				ScimUser existingUser = users.iterator().next();
				String id = existingUser.getId();
				int version = existingUser.getVersion();
				scimUser.setVersion(version);
				scimUser = scimUserProvisioning.update(id, scimUser);
				scimUserProvisioning.changePassword(id, null, user.getPassword());
			}
		}
		if (scimGroupProvisioning != null && membershipManager != null) {
			for (String g : groupsToAddUser) {
				addToGroup(scimUser, g);
			}
		}
		return scimUser;
	}
	
	@Override
	public void onApplicationEvent(NewUserAuthenticatedEvent event) {
		addUser(event.getUser());
	}

	private void addToGroup(ScimUser user, String gName) {
		if (!StringUtils.hasText(gName)) {
			return;
		}
		List<ScimGroup> g = scimGroupProvisioning.query(String.format("displayName eq '%s'", gName));
		ScimGroup group;
		if (g == null || g.isEmpty()) {
			group = new ScimGroup(gName);
			group = scimGroupProvisioning.create(group);
		} else {
			group = g.get(0);
		}
		try {
			membershipManager.addMember(group.getId(), new ScimGroupMember(user.getId()));
		} catch (MemberAlreadyExistsException ex) {
			// do nothing
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

	/**
	 * Convert authorities to groups.
	 */
	private Collection<Group> getGroups(List<? extends GrantedAuthority> authorities) {
		List<Group> groups = new ArrayList<Group>();
		for (GrantedAuthority group : authorities) {
			groups.add(new Group(null, group.toString()));
		}
		return groups;
	}
}
