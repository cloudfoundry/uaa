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
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScimGroupMember<TEntity extends ScimCore> {

    public TEntity getEntity() {
        return entity;
    }

    public void setEntity(TEntity entity) {
        this.entity = entity;
    }

    public ScimGroupMember() {
    }

    public ScimGroupMember(String memberId) {
        this(memberId, Type.USER);
    }

    public ScimGroupMember(TEntity entity) {
        this(entity.getId(), getEntityType(entity));
        setEntity(entity);
    }

    public ScimGroupMember(String memberId, Type type) {
        this.memberId = memberId;
        this.type = type;
    }

    @JsonProperty("value")
    private String memberId;

    private String origin = OriginKeys.UAA;

    private String operation;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public enum Type {
        USER, GROUP
    }

    private Type type;

    private TEntity entity;

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

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    @Override
    public String toString() {
        return "(memberId: %s, type: %s, origin:%s)".formatted(getMemberId(), getType(), getOrigin());
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        //don't allow null values
        if (origin == null) {
            throw new NullPointerException();
        }
        this.origin = origin;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ScimGroupMember member = (ScimGroupMember) o;
        if (getMemberId() != null ? !getMemberId().equals(member.getMemberId()) : member.getMemberId() != null) {
            return false;
        }
        return getType() == member.getType();
    }

    @Override
    public int hashCode() {
        int result = getMemberId() != null ? getMemberId().hashCode() : 0;
        result = 31 * result + (getOrigin() != null ? getOrigin().hashCode() : 0);
        result = 31 * result + (getType() != null ? getType().hashCode() : 0);
        return result;
    }


    private static Type getEntityType(ScimCore entity) {
        Type type = null;
        if (entity instanceof ScimGroup) {
            type = Type.GROUP;
        } else if (entity instanceof ScimUser) {
            type = Type.USER;
        }
        return type;
    }
}
