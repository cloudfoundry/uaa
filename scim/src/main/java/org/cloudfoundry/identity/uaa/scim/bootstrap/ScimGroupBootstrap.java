/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.bootstrap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.dao.common.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimCoreInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimUserInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

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

    public ScimGroupBootstrap(ScimGroupProvisioning scimGroupProvisioning, ScimUserProvisioning scimUserProvisioning,
                    ScimGroupMembershipManager membershipManager) {
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.scimUserProvisioning = scimUserProvisioning;
        this.membershipManager = membershipManager;
        groups = new HashSet<String>();
        groupMembers = new HashMap<String, Set<String>>();
        groupAdmins = new HashMap<String, Set<String>>();
    }

    /**
     * Specify the list of groups to create as a comma-separated list of
     * group-names
     *
     * @param groups
     */
    public void setGroups(String groups) {
        this.groups = StringUtils.commaDelimitedListToSet(groups);
    }

    /**
     * Specify the membership info as a list of strings, where each string takes
     * the format -
     * <group-name>|<comma-separated usernames of members>[|write]
     * the optional 'write' field in the end marks the users as admins of the
     * group
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

    private void addMembers(String g) {
        ScimGroupInterface group = getGroup(g);
        if (group == null) {
            addGroup(g);
        }
        List<ScimGroupMemberInterface> members = getMembers(groupMembers.get(g), ScimGroupMemberInterface.GROUP_MEMBER);
        members.addAll(getMembers(groupAdmins.get(g), ScimGroupMemberInterface.GROUP_ADMIN));
        logger.debug("adding members: " + members + " into group: " + g);

        for (ScimGroupMemberInterface member : members) {
            try {
                membershipManager.addMember(group.getId(), member);
            } catch (MemberAlreadyExistsException ex) {
                logger.debug(member.getMemberId() + " already is member of group " + g);
            }
        }
    }

    private List<ScimGroupMemberInterface> getMembers(Set<String> names, List<ScimGroupMemberInterface.Role> auth) {
        if (names == null || names.isEmpty()) {
            return Collections.<ScimGroupMemberInterface> emptyList();
        }

        List<ScimGroupMemberInterface> members = new ArrayList<ScimGroupMemberInterface>();
        for (String name : names) {
            ScimCoreInterface member = getScimResourceId(name);
            if (member != null) {
                members.add(new ScimGroupMember(member.getId(),
                                (member instanceof ScimGroupInterface) ? ScimGroupMemberInterface.Type.GROUP : ScimGroupMemberInterface.Type.USER,
                                auth));
            }
        }
        return members;
    }

    private ScimCoreInterface getScimResourceId(String name) {

        ScimCoreInterface res = getUser(name);
        if (res != null) {
            return res;
        }

        logger.debug("user " + name + " does not exist, checking in groups...");
        return getGroup(name);
    }

    private ScimUserInterface getUser(String name) {
        List<ScimUserInterface> user = scimUserProvisioning.query(String.format(USER_BY_NAME_FILTER, name));
        if (user != null && !user.isEmpty()) {
            return user.get(0);
        }
        return null;
    }

    ScimGroupInterface getGroup(String name) {
        List<ScimGroupInterface> g = scimGroupProvisioning.query(String.format(GROUP_BY_NAME_FILTER, name));
        if (g != null && !g.isEmpty()) {
            ScimGroupInterface gr = g.get(0);
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
