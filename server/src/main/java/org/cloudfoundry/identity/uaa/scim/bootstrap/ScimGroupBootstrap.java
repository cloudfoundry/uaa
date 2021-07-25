/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ScimGroupBootstrap implements InitializingBean {

    private Map<String, String> groups;

    private Map<String, Set<String>> groupMembers;

    private Map<String, Set<String>> groupAdmins;

    private final ScimGroupProvisioning scimGroupProvisioning;

    private final ScimGroupMembershipManager membershipManager;

    private final ScimUserProvisioning scimUserProvisioning;

    private Map<String, String> defaultUserGroups = Collections.EMPTY_MAP;
    private Map<String,String> nonDefaultUserGroups = Collections.EMPTY_MAP;

    private Map<String, String> configuredGroups = Collections.EMPTY_MAP;

    private static final String USER_BY_NAME_FILTER = "username eq \"%s\"";

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private PropertySource messageSource;
    private String messagePropertyNameTemplate = "scope.%s";
    private final MapCollector<String, String, String> collector = new MapCollector<>(
        g -> g,
        g -> (String) getMessageSource().getProperty(String.format(messagePropertyNameTemplate, g))
    );

    public String getMessagePropertyNameTemplate() {
        return messagePropertyNameTemplate;
    }

    public void setMessagePropertyNameTemplate(String messagePropertyNameTemplate) {
        this.messagePropertyNameTemplate = messagePropertyNameTemplate;
    }

    public ScimGroupBootstrap(ScimGroupProvisioning scimGroupProvisioning, ScimUserProvisioning scimUserProvisioning,
                    ScimGroupMembershipManager membershipManager) {
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.scimUserProvisioning = scimUserProvisioning;
        this.membershipManager = membershipManager;
        groups = new HashMap<>();
        groupMembers = new HashMap<>();
        groupAdmins = new HashMap<>();
    }

    public PropertySource getMessageSource() {
        if(messageSource == null) {
            String messagesFilename = "messages.properties";
            try {
                messageSource = new ResourcePropertySource(messagesFilename);
            } catch(IOException ex) {
                messageSource = new PropertySource.StubPropertySource(messagesFilename);
            }
        }

        return messageSource;
    }

    public void setMessageSource(PropertySource messageSource) {
        this.messageSource = messageSource;
    }

    /**
     * Specify the list of groups to create as a comma-separated list of
     * group-names
     *
     * @param groups
     */
    public void setGroups(Map<String,String> groups) {
        if(groups==null) { groups = Collections.EMPTY_MAP; }
        groups.entrySet().forEach(e -> {
            if(!StringUtils.hasText(e.getValue())) { e.setValue((String) getMessageSource().getProperty(String.format(messagePropertyNameTemplate, e.getKey()))); }
        });
        this.configuredGroups = groups;
        setCombinedGroups();
    }

    public void setDefaultUserGroups(Set<String> defaultUserGroups) {
        if(defaultUserGroups==null) { defaultUserGroups = Collections.EMPTY_SET; }
        this.defaultUserGroups = defaultUserGroups.stream()
            .collect(collector);

        setCombinedGroups();
    }

    public void setNonDefaultUserGroups(Set<String> nonDefaultUserGroups) {
        if(nonDefaultUserGroups==null) { nonDefaultUserGroups = Collections.EMPTY_SET; }
        this.nonDefaultUserGroups = nonDefaultUserGroups.stream()
            .collect(collector);

        setCombinedGroups();
    }

    private void setCombinedGroups() {
        this.groups = new HashMap<>();
        this.groups.putAll(this.defaultUserGroups);
        this.groups.putAll(this.nonDefaultUserGroups);

        this.configuredGroups.entrySet().stream()
            .filter(e -> StringUtils.hasText(e.getValue()) || !groups.containsKey(e.getKey()))
            .forEach(e -> groups.put(e.getKey(), e.getValue()));

        this.groups = this.groups.entrySet().stream()
            .collect(new MapCollector<>(e -> StringUtils.trimWhitespace(e.getKey()), e -> StringUtils.trimWhitespace(e.getValue())));
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
            groups.putIfAbsent(groupName, null);

            boolean groupAdmin = 3 <= fields.length && "write".equalsIgnoreCase(fields[2]);
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
    public void afterPropertiesSet() {
        List<ScimGroup> groupInfos = groups.keySet().stream().filter(n -> StringUtils.hasText(n)).map(n -> getOrCreateGroup(n)).collect(Collectors.toList());
        for (int i = 0; i < groupInfos.size(); i++) {
            ScimGroup g = groupInfos.get(i);
            String description = groups.get(g.getDisplayName());
            if (StringUtils.hasText(description)) {
                g.setDescription(description);
                try{
                    groupInfos.set(i, scimGroupProvisioning.update(g.getId(), g, IdentityZoneHolder.get().getId()));
                } catch(IncorrectResultSizeDataAccessException e) {
                    ScimGroup updatedGroup = getGroup(g.getDisplayName());
                    if(updatedGroup != null && updatedGroup.getVersion() > g.getVersion()) {
                        logger.debug("Group has already been updated by another instance, ignore error.");
                    } else {
                        throw e;
                    }
                }
            }
        }

        for (ScimGroup g : groupInfos) {
            addMembers(g);
        }
    }

    private void addMembers(ScimGroup group) {
        String name = group.getDisplayName();
        List<ScimGroupMember> members = getMembers(groupMembers.get(name));
        members.addAll(getMembers(groupAdmins.get(name)));
        logger.debug("adding members: " + members + " into group: " + name);

        for (ScimGroupMember member : members) {
            try {
                membershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());
            } catch (MemberAlreadyExistsException ex) {
                logger.debug(member.getMemberId() + " already is member of group " + name);
            }
        }
    }

    private List<ScimGroupMember> getMembers(Set<String> names) {
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
                        (member instanceof ScimGroup) ? ScimGroupMember.Type.GROUP : ScimGroupMember.Type.USER
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
        List<ScimUser> user = scimUserProvisioning.query(String.format(USER_BY_NAME_FILTER, name), IdentityZoneHolder.get().getId());
        if (user != null && !user.isEmpty()) {
            return user.get(0);
        }
        return null;
    }

    ScimGroup getGroup(String name) {
        try {
            ScimGroup gr = scimGroupProvisioning.getByName(name, IdentityZoneHolder.get().getId());
            gr.setMembers(membershipManager.getMembers(gr.getId(), false, IdentityZoneHolder.get().getId()));
            return gr;
        } catch (ScimResourceNotFoundException | IncorrectResultSizeDataAccessException e) {
            logger.debug("could not find group with name");
            return null;
        }
    }

    private ScimGroup getOrCreateGroup(String name) {
        logger.debug("adding group: " + name);
        String uaaZoneId = IdentityZone.getUaaZoneId();
        return scimGroupProvisioning.createOrGet(new ScimGroup(null, name, uaaZoneId), uaaZoneId);
    }
}
