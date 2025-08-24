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


import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimGroupExternalMember extends ScimCore<ScimGroupExternalMember> {

    private String groupId;

    private String externalGroup;

    private String displayName;

    private String origin;

    public ScimGroupExternalMember() {
    }


    public ScimGroupExternalMember(String groupId, String externalGroup) {
        this.groupId = groupId;
        this.externalGroup = externalGroup;
    }

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public String getExternalGroup() {
        return externalGroup;
    }

    public void setExternalGroup(String externalGroup) {
        this.externalGroup = externalGroup;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    @Override
    public String toString() {
        return "(Group id: %s, Name: %s, externalGroup: %s, origin: %s)".formatted(
                getGroupId(),
                getDisplayName(),
                getExternalGroup(),
                getOrigin());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        ScimGroupExternalMember that = (ScimGroupExternalMember) o;
        if (!getGroupId().equals(that.getGroupId())) {
            return false;
        }
        if (!getExternalGroup().equals(that.getExternalGroup())) {
            return false;
        }
        return getOrigin() == null ? that.getOrigin() != null : !getOrigin().equals(that.getOrigin());
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + getGroupId().hashCode();
        result = 31 * result + getExternalGroup().hashCode();
        result = 31 * result + (getOrigin() != null ? getOrigin().hashCode() : 0);
        return result;
    }
}
