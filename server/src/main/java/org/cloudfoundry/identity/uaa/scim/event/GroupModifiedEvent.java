/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.scim.event;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.core.Authentication;

import java.util.Arrays;

public class GroupModifiedEvent extends AbstractUaaEvent {

    private final String groupId;
    private final String groupName;
    private final String[] members;
    private final AuditEventType eventType;

    protected GroupModifiedEvent(String groupId, String name, String[] members, AuditEventType type, Authentication authentication, String zoneId) {
        super(authentication, zoneId);
        this.groupId = groupId;
        this.groupName = name;
        this.members = members;
        this.eventType = type;
    }

    public static GroupModifiedEvent groupCreated(String group, String name, String[] members, String zoneId) {
        return new GroupModifiedEvent(
                group,
                name,
                members,
                AuditEventType.GroupCreatedEvent,
                getContextAuthentication(),
                zoneId);
    }

    public static GroupModifiedEvent groupModified(String group, String name, String[] members, String zoneId) {
        return new GroupModifiedEvent(
                group,
                name,
                members,
                AuditEventType.GroupModifiedEvent,
                getContextAuthentication(),
                zoneId);
    }

    public static GroupModifiedEvent groupDeleted(String group, String name, String[] members, String zoneId) {
        return new GroupModifiedEvent(
                group,
                name,
                members,
                AuditEventType.GroupDeletedEvent,
                getContextAuthentication(),
                zoneId);
    }

    @Override
    public AuditEvent getAuditEvent() {
        String data = JsonUtils.writeValueAsString(new GroupInfo(groupName, members));
        return createAuditRecord(
                groupId,
                eventType,
                getOrigin(getAuthentication()),
                data);
    }

    public String getGroupId() {
        return groupId;
    }

    public String[] getMembers() {
        return members;
    }

    public static class GroupInfo {
        @JsonIgnore
        private String group;
        @JsonIgnore
        private String[] members;

        @JsonCreator
        public GroupInfo(@JsonProperty("group_name") String g, @JsonProperty("members") String[] m) {
            this.group = g;
            this.members = m;
            //sort for equals() to work
            Arrays.sort(members);
        }

        @JsonProperty("group_name")
        public String getGroup() {
            return group;
        }

        @JsonProperty("members")
        public String[] getMembers() {
            return members;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            GroupInfo groupInfo = (GroupInfo) o;

            if (!group.equals(groupInfo.group)) {
                return false;
            }
            return Arrays.equals(members, groupInfo.members);
        }

        @Override
        public int hashCode() {
            int result = group.hashCode();
            result = 31 * result + Arrays.hashCode(members);
            return result;
        }

        @Override
        public String toString() {
            return "GroupInfo{" +
                    "group='" + group + '\'' +
                    ", members=" + Arrays.toString(members) +
                    '}';
        }
    }
}
