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
package org.cloudfoundry.identity.uaa.scim;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.List;


@JsonSerialize(using = ScimGroupJsonSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
@JsonDeserialize(using = ScimGroupJsonDeserializer.class)
public class ScimGroup extends ScimCore {

    private String displayName;
    private List<ScimGroupMember> members;

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public List<ScimGroupMember> getMembers() {
        return members;
    }

    public void setMembers(List<ScimGroupMember> members) {
        this.members = members;
    }

    public ScimGroup() {
    }

    public ScimGroup(String name) {
        this.displayName = name;
    }

    public ScimGroup(String id, String name) {
        super(id);
        this.displayName = name;
    }

    @Override
    public String toString() {
        return String.format("(Group id: %s, name: %s, created: %s, modified: %s, version: %s, members: %s)", getId(),
                        displayName, getMeta().getCreated(), getMeta().getLastModified(), getVersion(), members);
    }
}
