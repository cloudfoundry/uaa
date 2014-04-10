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

import java.util.Arrays;
import java.util.List;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class ScimGroupMember {

    @JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
    public static enum Role {
        MEMBER, READER, WRITER;
    }

    public static final List<Role> GROUP_MEMBER = Arrays.asList(Role.MEMBER);
    public static final List<Role> GROUP_ADMIN = Arrays.asList(Role.READER, Role.WRITER);

    @JsonProperty("value")
    private String memberId;

    @JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
    public enum Type {
        USER, GROUP
    }

    private Type type;

    @JsonIgnore
    private List<Role> roles;

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> permissions) {
        this.roles = permissions;
    }

    public String getMemberId() {
        return memberId;
    }

    public void setMemberId(String memberId) {
        this.memberId = memberId;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
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
        this(memberId, Type.USER, GROUP_MEMBER);
    }

    public ScimGroupMember(String memberId, Type type, List<Role> roles) {
        this.memberId = memberId;
        this.type = type;
        this.roles = roles;
    }
}
