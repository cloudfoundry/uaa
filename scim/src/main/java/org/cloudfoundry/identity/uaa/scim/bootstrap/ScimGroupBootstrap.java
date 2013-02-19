package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ScimGroupBootstrap implements InitializingBean {

	private Set<String> groups;

	private Map<String, Set<String>> groupMembers;

	private Map<String, Set<String>> groupAdmins;

	private final ScimGroupProvisioning scimGroupProvisioning;

	private final ScimGroupMembershipManager membershipManager;

	private final ScimUserProvisioning scimUserProvisioning;

	private static final String USER_BY_NAME_FILTER = "username eq '%s'";

	private static final String GROUP_BY_NAME_FILTER = "displayName eq '%s'";

	private final Log logger = LogFactory.getLog(getClass());

	public ScimGroupBootstrap(ScimGroupProvisioning scimGroupProvisioning, ScimUserProvisioning scimUserProvisioning, ScimGroupMembershipManager membershipManager) {
		this.scimGroupProvisioning = scimGroupProvisioning;
		this.scimUserProvisioning = scimUserProvisioning;
		this.membershipManager = membershipManager;
		groups = new HashSet<String>();
		groupMembers = new HashMap<String, Set<String>>();
		groupAdmins = new HashMap<String, Set<String>>();
	}

	/**
	 * Specify the list of groups to create as a comma-separated list of group-names
	 *
	 * @param groups
	 */
	public void setGroups(String groups) {
		this.groups = StringUtils.commaDelimitedListToSet(groups);
	}

	/**
	 * Specify the membership info as a list of strings, where each string takes the format -
	 * 		<group-name>|<comma-separated usernames of members>[|write]
	 * the optional 'write' field in the end marks the users as admins of the group
	 *
	 * @param membershipInfo
	 */
	public void setGroupMembers(List<String> membershipInfo) {
		for (String line : membershipInfo) {
			String[] fields = line.split("\\|");
			if (fields.length < 2) {
				continue;
			}
			Set<String> users = StringUtils.commaDelimitedListToSet(fields[1]);
			String groupName = fields[0];
			groups.add(groupName);

			boolean groupAdmin = (3 <= fields.length && "write".equalsIgnoreCase(fields[2])) ? true : false;
			if (groupAdmin) {
				groupAdmins.put(groupName, users);
			} else {
				groupMembers.put(groupName, users);
			}
		}
		logger.debug("groups: " + groups);
		logger.debug("admins: " + groupAdmins + ", members: " + groupMembers);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		for (String g : groups) {
			addGroup(g);
		}
		for (String g : groups) {
			addMembers(g);
		}
	}

	private void addMembers (String g) {
		ScimGroup group = getGroup(g);
		if (group == null) {
			addGroup(g);
		}
        List<ScimGroupMember> members = getMembers(groupMembers.get(g), ScimGroupMember.GROUP_MEMBER);
		members.addAll(getMembers(groupAdmins.get(g), ScimGroupMember.GROUP_ADMIN));
		logger.debug("adding members: " + members + " into group: " + g);

		for (ScimGroupMember member : members) {
			try {
				membershipManager.addMember(group.getId(), member);
			} catch (MemberAlreadyExistsException ex) {
				logger.debug(member.getMemberId() + " already is member of group " + g);
			}
		}
	}

	private List<ScimGroupMember> getMembers(Set<String> names, List<ScimGroupMember.Role> auth) {
		if (names == null || names.isEmpty()) {
			return Collections.<ScimGroupMember>emptyList();
		}

		List<ScimGroupMember> members = new ArrayList<ScimGroupMember>();
		for (String name : names) {
			ScimCore member = getScimResourceId(name);
			if (member != null) {
				members.add(new ScimGroupMember(member.getId(), (member instanceof ScimGroup) ? ScimGroupMember.Type.GROUP : ScimGroupMember.Type.USER, auth));
			}
		}
		return members;
	}

	private ScimCore getScimResourceId(String name) {

		ScimCore res = getUser(name);
		if (res != null) {
			return res;
		}

		logger.debug("user " + name + " does not exist, checking in groups...");
		return getGroup(name);
	}

	private ScimUser getUser(String name) {
		List<ScimUser> user = scimUserProvisioning.query(String.format(USER_BY_NAME_FILTER, name));
		if (user != null && !user.isEmpty()) {
			return user.get(0);
		}
		return null;
	}

	ScimGroup getGroup(String name) {
		List<ScimGroup> g = scimGroupProvisioning.query(String.format(GROUP_BY_NAME_FILTER, name));
		if (g != null && !g.isEmpty()) {
			ScimGroup gr =  g.get(0);
			gr.setMembers(membershipManager.getMembers(gr.getId()));
			return gr;
		}
		logger.debug("could not find group with name");
		return null;
	}

	private void addGroup(String name) {
        if (name.isEmpty()) {
            return;
        }
		logger.debug("adding group: " + name);
		ScimGroup g = new ScimGroup(name);
		try {
			scimGroupProvisioning.create(g);
		} catch (ScimResourceAlreadyExistsException ex) {
		    logger.debug("group " + g + " already exists, ignoring...");
		}
	}
}
