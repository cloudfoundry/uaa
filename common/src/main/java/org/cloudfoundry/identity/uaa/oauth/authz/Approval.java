package org.cloudfoundry.identity.uaa.oauth.authz;

import org.codehaus.jackson.map.annotate.JsonSerialize;

import java.util.Date;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class Approval {

	private static final long THIRTY_MINUTES_IN_MILLIS = 1800000;

	private String userId;

	private String clientId;

	private String scope;

	private Date expiresAt;

	public String getUserName() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId == null ? "" : userId;
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

	public Date getExpiresAt() {
		return expiresAt;
	}

	public void setExpiresAt(Date expiresAt) {
		this.expiresAt = expiresAt == null ? new Date(new Date().getTime() + THIRTY_MINUTES_IN_MILLIS) : expiresAt;
	}

	public Approval(String userId, String clientId, String scope, long expiresIn) {
		this(userId, clientId, scope, new Date(new Date().getTime() + expiresIn));
	}

	public Approval(String userId, String clientId, String scope, Date expiresAt) {
		this.userId = userId;
		this.clientId = clientId;
		this.scope = scope;
		this.expiresAt = expiresAt;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + userId.hashCode();
		result = prime * result + clientId.hashCode();
		result = prime * result + scope.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null || !(o instanceof Approval)) {
			return false;
		}
		Approval other = (Approval) o;
		return userId == other.userId && clientId == other.clientId && scope == other.scope;
	}

	@Override
	public String toString() {
		return String.format("user %s delegated scope %s to client %s until %s", userId, scope, clientId, expiresAt);
	}
}
