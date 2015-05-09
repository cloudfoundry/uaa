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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.authentication.Origin;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimGroupMember {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static enum Role {
        MEMBER, READER, WRITER;
    }

    public static final List<Role> GROUP_MEMBER = Arrays.asList(Role.MEMBER);
    public static final List<Role> GROUP_ADMIN = Arrays.asList(Role.READER, Role.WRITER);

    @JsonProperty("value")
    private String memberId;

    private String origin = Origin.UAA;

    @JsonInclude(JsonInclude.Include.NON_NULL)
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

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        //don't allow null values
        if (origin==null) {
            throw new NullPointerException();
        }
        this.origin = origin;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ScimGroupMember that = (ScimGroupMember) o;

        if (!memberId.equals(that.memberId)) return false;
        if (!origin.equals(that.origin)) return false;
        if (type != that.type) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = memberId.hashCode();
        result = 31 * result + origin.hashCode();
        result = 31 * result + type.hashCode();
        return result;
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
