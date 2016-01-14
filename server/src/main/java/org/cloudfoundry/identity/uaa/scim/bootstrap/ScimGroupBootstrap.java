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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.util.StringUtils;

public class ScimGroupBootstrap implements InitializingBean {

    private Set<String> groups;

    private Map<String, Set<String>> groupMembers;

    private Map<String, Set<String>> groupAdmins;

    private final ScimGroupProvisioning scimGroupProvisioning;

    private final ScimGroupMembershipManager membershipManager;

    private final ScimUserProvisioning scimUserProvisioning;

    private Set<String> defaultUserGroups = Collections.EMPTY_SET;
    private Set<String> commaSeparatedGroups = Collections.EMPTY_SET;

    private static final String USER_BY_NAME_FILTER = "username eq \"%s\"";

    private static final String GROUP_BY_NAME_FILTER = "displayName eq \"%s\"";

    private final Log logger = LogFactory.getLog(getClass());

    private final PropertySource messages;

    public ScimGroupBootstrap(ScimGroupProvisioning scimGroupProvisioning, ScimUserProvisioning scimUserProvisioning,
                    ScimGroupMembershipManager membershipManager) {
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.scimUserProvisioning = scimUserProvisioning;
        this.membershipManager = membershipManager;
        groups = new HashSet<>();
        groupMembers = new HashMap<>();
        groupAdmins = new HashMap<>();

        PropertySource messagesPropertySource;
        String messagesFilename = "messages.properties";
        try {
            messagesPropertySource = new ResourcePropertySource(messagesFilename);
        } catch(IOException ex) {
            messagesPropertySource = new PropertySource.StubPropertySource(messagesFilename);
        }
        messages = messagesPropertySource;
    }

    /**
     * Specify the list of groups to create as a comma-separated list of
     * group-names
     *
     * @param commaSeparatedGroups
     */
    public void setGroups(String commaSeparatedGroups) {
        this.commaSeparatedGroups = StringUtils.commaDelimitedListToSet(commaSeparatedGroups);
        this.groups = new HashSet<>();
        this.groups.addAll(this.commaSeparatedGroups);
        this.groups.addAll(this.defaultUserGroups);
    }

    /**
     * Specify the membership info as a list of strings, where each string takes
     * the format -
     * {@code <group-name>|<comma-separated usernames of members>[|write]}
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
        List<ScimGroup> groupInfos = groups.stream().filter(n -> StringUtils.hasText(n)).map(n -> getOrCreateGroup(n)).collect(Collectors.toList());
        for (int i = 0; i < groupInfos.size(); i++) {
            ScimGroup g = groupInfos.get(i);
            String description = (String) messages.getProperty("scope." + g.getDisplayName());
            if (StringUtils.hasText(description)) {
                g.setDescription(description);
                groupInfos.set(i, scimGroupProvisioning.update(g.getId(), g));
            }
        }

        for (ScimGroup g : groupInfos) {
            addMembers(g);
        }
    }

    private void addMembers(ScimGroup group) {
        String name = group.getDisplayName();
        List<ScimGroupMember> members = getMembers(groupMembers.get(name), ScimGroupMember.GROUP_MEMBER);
        members.addAll(getMembers(groupAdmins.get(name), ScimGroupMember.GROUP_ADMIN));
        logger.debug("adding members: " + members + " into group: " + name);

        for (ScimGroupMember member : members) {
            try {
                membershipManager.addMember(group.getId(), member);
            } catch (MemberAlreadyExistsException ex) {
                logger.debug(member.getMemberId() + " already is member of group " + name);
            }
        }
    }

    private List<ScimGroupMember> getMembers(Set<String> names, List<ScimGroupMember.Role> auth) {
        if (names == null || names.isEmpty()) {
            return Collections.<ScimGroupMember> emptyList();
        }

        List<ScimGroupMember> members = new ArrayList<>();
        for (String name : names) {
            ScimCore member = getScimResourceId(name);
            if (member != null) {
                members.add(
                    new ScimGroupMember(
                        member.getId(),
                        (member instanceof ScimGroup) ? ScimGroupMember.Type.GROUP : ScimGroupMember.Type.USER,
                        auth
                    )
                );
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
            ScimGroup gr = g.get(0);
            gr.setMembers(membershipManager.getMembers(gr.getId()));
            return gr;
        }
        logger.debug("could not find group with name");
        return null;
    }

    private ScimGroup getOrCreateGroup(String name) {
        logger.debug("adding group: " + name);
        ScimGroup g = new ScimGroup(null,name,IdentityZoneHolder.get().getId());
        try {
            g = scimGroupProvisioning.create(g);
        } catch (ScimResourceAlreadyExistsException ex) {
            logger.debug("group " + g + " already exists, retrieving...");
            g = getGroup(name);
        }
        return g;
    }

    public Set<String> getDefaultUserGroups() {
        return defaultUserGroups;
    }

    public void setDefaultUserGroups(Set<String> defaultUserGroups) {
        this.defaultUserGroups = defaultUserGroups;
        this.groups = new HashSet<>();
        this.groups.addAll(this.commaSeparatedGroups);
        this.groups.addAll(this.defaultUserGroups);
    }
}
