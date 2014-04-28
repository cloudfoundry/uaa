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
package org.cloudfoundry.identity.uaa.scim.domain.standard;

import java.util.ArrayList;
import java.util.List;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.cloudfoundry.identity.uaa.scim.json.ScimGroupJsonDeserializer;
import org.cloudfoundry.identity.uaa.scim.json.ScimGroupJsonSerializer;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(using = ScimGroupJsonSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
@JsonDeserialize(using = ScimGroupJsonDeserializer.class)
public class ScimGroup extends ScimCore implements ScimGroupInterface {

    private String displayName;
    private List<ScimGroupMember> members;

    @Override
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    @Override
    public List<? extends ScimGroupMemberInterface> getMembers() {
        return members;
    }

    @Override
    public void setMembers(List<ScimGroupMemberInterface> members) {
        if (members == null)
        {
            this.members = null;
        }
        else
        {
            this.members = new ArrayList<ScimGroupMember>();
            for (ScimGroupMemberInterface item : members)
            {
                this.members.add((ScimGroupMember) item);
            }
        }
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
    public ScimUserGroup getUserGroup()
    {
        return new ScimUserGroup(getId(), getDisplayName());
    }

    @Override
    public String toString() {
        return String.format("(Group id: %s, name: %s, created: %s, modified: %s, version: %s, members: %s)", getId(),
                        displayName, getMeta().getCreated(), getMeta().getLastModified(), getVersion(), members);
    }
}
