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
package org.cloudfoundry.identity.uaa.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.List;


@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScimGroup extends ScimCore {

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
        this(null,name,null);
    }

    public ScimGroup(String id, String name, String zoneId) {
        super(id);
        this.displayName = name;
        this.zoneId = zoneId;
    }

    @Override
    public String toString() {
        return String.format("(Group id: %s, name: %s, description: %s, created: %s, modified: %s, version: %s, members: %s)",
                             getId(),
                             displayName,
                             description,
                             getMeta().getCreated(),
                             getMeta().getLastModified(),
                             getVersion(),
                             members);
    }
}
