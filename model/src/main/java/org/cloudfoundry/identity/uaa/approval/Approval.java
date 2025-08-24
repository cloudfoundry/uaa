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
package org.cloudfoundry.identity.uaa.approval;

import java.util.Calendar;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.cloudfoundry.identity.uaa.impl.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.impl.JsonDateSerializer;
import org.cloudfoundry.identity.uaa.approval.impl.ApprovalsJsonDeserializer;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonDeserialize(using = ApprovalsJsonDeserializer.class)
public class Approval {

    public Approval() {
    }

    public enum ApprovalStatus {
        APPROVED,
        DENIED
    }

    private String userId = "";

    private String clientId = "";

    private String scope = "";

    private ApprovalStatus status;

    private Date expiresAt;

    private Date lastUpdatedAt = new Date();

    public static Date timeFromNow(int timeTill) {
        Calendar timeOf = Calendar.getInstance();
        timeOf.add(Calendar.MILLISECOND, timeTill);
        return timeOf.getTime();
    }

    public String getUserId() {
        return userId;
    }

    public Approval setUserId(String userId) {
        this.userId = userId == null ? "" : userId;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public Approval setClientId(String clientId) {
        this.clientId = clientId == null ? "" : clientId;
        return this;
    }

    public ApprovalStatus getStatus() {
        return status;
    }

    public String getScope() {
        return scope;
    }

    public Approval setScope(String scope) {
        this.scope = scope == null ? "" : scope;
        return this;
    }

    @JsonSerialize(using = JsonDateSerializer.class)
    @JsonProperty("expiresAt")
    public Date getExpiresAt() {
        if (expiresAt == null) {
            Calendar thirtyMinFromNow = Calendar.getInstance();
            thirtyMinFromNow.add(Calendar.MINUTE, 30);
            expiresAt = thirtyMinFromNow.getTime();
        }
        return expiresAt;
    }

    @JsonDeserialize(using = JsonDateDeserializer.class)
    @JsonProperty("expiresAt")
    public Approval setExpiresAt(Date expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }

    @JsonSerialize(using = JsonDateSerializer.class)
    public Date getLastUpdatedAt() {
        return lastUpdatedAt;
    }

    @JsonDeserialize(using = JsonDateDeserializer.class)
    public Approval setLastUpdatedAt(Date lastUpdatedAt) {
        if (lastUpdatedAt == null) {
            throw new IllegalArgumentException("lastUpdatedAt cannot be null");
        }
        this.lastUpdatedAt = lastUpdatedAt;
        return this;
    }

    @JsonIgnore
    public boolean isActiveAsOf(Date currentDate) {
        return expiresAt != null && expiresAt.after(currentDate);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + userId.hashCode();
        result = prime * result + clientId.hashCode();
        result = prime * result + scope.hashCode();
        result = prime * result + status.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !(o instanceof Approval)) {
            return false;
        }
        Approval other = (Approval) o;
        return userId.equals(other.userId) && clientId.equals(other.clientId) && scope.equals(other.scope)
                && status == other.status;
    }

    @Override
    public String toString() {
        return "[%s, %s, %s, %s, %s, %s]".formatted(userId, scope, clientId, expiresAt, status.toString(),
                lastUpdatedAt);
    }

    public Approval setStatus(ApprovalStatus status) {
        this.status = status;
        return this;
    }

}
