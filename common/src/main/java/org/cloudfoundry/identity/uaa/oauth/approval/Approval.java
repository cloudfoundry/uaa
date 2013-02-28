/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth.approval;

import java.util.Calendar;
import java.util.Date;

import org.cloudfoundry.identity.uaa.util.json.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.util.json.JsonDateSerializer;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class Approval {

	private String userName;

	private String clientId;

	private String scope;

	public enum ApprovalStatus {
		APPROVED,
		DENIED;
	}

	private ApprovalStatus status;

	public ApprovalStatus getStatus() {
		return status;
	}

	private Date expiresAt;

	private Date lastUpdatedAt;

	public String getUserName() {
		return userName;
	}

	public void setUserId(String userId) {
		this.userName = userId == null ? "" : userId;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId == null ? "" : clientId;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope == null ? "" : scope;
	}

	@JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
	public Date getExpiresAt() {
		return expiresAt;
	}

	@JsonDeserialize(using = JsonDateDeserializer.class)
	public void setExpiresAt(Date expiresAt) {
		if (expiresAt == null) {
			Calendar thirtyMinFromNow = Calendar.getInstance();
			thirtyMinFromNow.add(Calendar.MINUTE, 30);
			expiresAt = thirtyMinFromNow.getTime();
		}
		this.expiresAt = expiresAt;
	}

	@JsonSerialize(using = JsonDateSerializer.class, include = JsonSerialize.Inclusion.NON_NULL)
	public Date getLastUpdatedAt() {
		return lastUpdatedAt;
	}

	@JsonDeserialize(using = JsonDateDeserializer.class)
	public void setLastUpdatedAt(Date lastUpdatedAt) {
		this.lastUpdatedAt = lastUpdatedAt;
	}

	@JsonIgnore
	public boolean isCurrentlyActive() {
		return expiresAt != null && expiresAt.after(new Date());
	}

	public Approval(String userId, String clientId, String scope, int expiresIn, ApprovalStatus status) {
		this(userId, clientId, scope, new Date(), status, new Date());
		Calendar expiresAt = Calendar.getInstance();
		expiresAt.add(Calendar.MILLISECOND, expiresIn);
		setExpiresAt(expiresAt.getTime());
	}

	public Approval(String userId, String clientId, String scope, Date expiresAt, ApprovalStatus status) {
		this(userId, clientId, scope, expiresAt, status, new Date());
	}

	public Approval(String userId, String clientId, String scope, Date expiresAt, ApprovalStatus status, Date lastUpdatedAt) {
		this.userName = userId;
		this.clientId = clientId;
		this.scope = scope;
		this.expiresAt = expiresAt;
		this.status = status;
		this.lastUpdatedAt = lastUpdatedAt;
	}

	public Approval() { }

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + userName.hashCode();
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
		return userName.equals(other.userName) && clientId.equals(other.clientId) && scope.equals(other.scope) && status == other.status;
	}

	@Override
	public String toString() {
		return String.format("[%s, %s, %s, %s, %s, %s]", userName, scope, clientId, expiresAt, status.toString(), lastUpdatedAt);
	}

	public void setStatus(ApprovalStatus status) {
		this.status = status;
	}

}
