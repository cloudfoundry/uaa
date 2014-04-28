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

import java.util.List;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class ScimGroupMember implements ScimGroupMemberInterface {

    @JsonProperty("value")
    private String memberId;

    private ScimGroupMemberInterface.Type type;

    @JsonIgnore
    private List<ScimGroupMemberInterface.Role> roles;

    @Override
    public List<ScimGroupMemberInterface.Role> getRoles() {
        return roles;
    }

    @Override
    public void setRoles(List<ScimGroupMemberInterface.Role> permissions) {
        this.roles = permissions;
    }

    @Override
    public String getMemberId() {
        return memberId;
    }

    @Override
    public void setMemberId(String memberId) {
        this.memberId = memberId;
    }

    @Override
    public ScimGroupMemberInterface.Type getType() {
        return type;
    }

    @Override
    public void setType(ScimGroupMemberInterface.Type type) {
        this.type = type;
    }

    @Override
    public String toString() {
        return String.format("(memberId: %s, type: %s, roles: %s)", memberId, type, roles);
    }

    @Override
    public int hashCode() {
        int hc = 31 ^ memberId.hashCode();
        hc ^= type.hashCode();
        return hc;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ScimGroupMember)) {
            return false;
        }
        ScimGroupMember other = (ScimGroupMember) o;
        if (memberId.equals(other.memberId) && type.equals(other.type)) {
            return true;
        }
        return false;
    }

    public ScimGroupMember() {
    }

    public ScimGroupMember(String memberId) {
        this(memberId, ScimGroupMemberInterface.Type.USER, GROUP_MEMBER);
    }

    public ScimGroupMember(String memberId, ScimGroupMemberInterface.Type type, List<ScimGroupMemberInterface.Role> roles) {
        this.memberId = memberId;
        this.type = type;
        this.roles = roles;
    }
}
