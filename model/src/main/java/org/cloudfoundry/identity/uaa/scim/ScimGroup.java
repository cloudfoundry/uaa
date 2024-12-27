/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;


@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScimGroup extends ScimCore<ScimGroup> {

    private String displayName;
    private String zoneId;
    private String description;

    private List<ScimGroupMember> members;

    public String getDisplayName() {
        return displayName;
    }

    public ScimGroup setDisplayName(String displayName) {
        this.displayName = displayName;
        return this;
    }

    public String getZoneId() {
        return zoneId;
    }

    public ScimGroup setZoneId(String zoneId) {
        this.zoneId = zoneId;
        return this;
    }

    public List<ScimGroupMember> getMembers() {
        return members;
    }

    public ScimGroup setMembers(List<ScimGroupMember> members) {
        this.members = members;
        return this;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public ScimGroup() {
        this(null);
    }

    public ScimGroup(String name) {
        this(null, name, null);
    }

    public ScimGroup(String id, String displayName, String zoneId) {
        super(id);
        this.displayName = displayName;
        this.zoneId = zoneId;
    }

    @Override
    public void patch(ScimGroup patch) {
        String[] attributes = ofNullable(patch.getMeta().getAttributes()).orElse(new String[0]);
        for (String attribute : attributes) {
            switch (attribute.toUpperCase()) {
                case "DESCRIPTION":
                    setDescription(null);
                    break;
                case "DISPLAYNAME":
                    setDisplayName(null);
                    break;
                case "ZONEID":
                    throw new IllegalArgumentException("Cannot delete or change ZoneId");
                case "ID":
                    throw new IllegalArgumentException("Cannot delete or change ID");
                case "MEMBERS":
                    setMembers(new ArrayList<>());
                    break;
                default:
                    throw new IllegalArgumentException("Attribute %s cannot be removed using \"Meta.attributes\"".formatted(attribute));
            }
        }

        if (patch.getMembers() != null) {
            //remove all members that are in the patch list
            Set<String> patchMemberIds = patch
                    .getMembers()
                    .stream()
                    .map(ScimGroupMember::getMemberId)
                    .collect(Collectors.toSet());
            List<ScimGroupMember> newMembers = new ArrayList<>(getMembers());
            newMembers.removeIf(member -> patchMemberIds.contains(member.getMemberId()));

            //add back all members that don't have "delete" as operation
            newMembers.addAll(
                    patch.getMembers()
                            .stream()
                            .filter(member -> !"delete".equalsIgnoreCase(member.getOperation()))
                            .toList()
            );

            setMembers(newMembers);
        }
        ofNullable(patch.getDescription()).ifPresent(this::setDescription);
        ofNullable(patch.getDisplayName()).ifPresent(this::setDisplayName);
    }

    @Override
    public String toString() {
        return "(Group id: %s, name: %s, description: %s, created: %s, modified: %s, version: %s, members: %s)".formatted(
                getId(),
                displayName,
                description,
                getMeta().getCreated(),
                getMeta().getLastModified(),
                getVersion(),
                members);
    }
}
