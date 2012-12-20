package org.cloudfoundry.identity.uaa.scim;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;

import java.util.List;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class ScimGroupMember {

	@JsonProperty("value")
	private String memberId;

	@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
	public enum Type {
		USER, GROUP
	}

	private Type type;

	@JsonIgnore
	private List<ScimGroup.Authority> authorities;

	public List<ScimGroup.Authority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(List<ScimGroup.Authority> permissions) {
		this.authorities = permissions;
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
		return String.format("(memberId: %s, type: %s, permissions: %s)", memberId, type, authorities);
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
		this(memberId, Type.USER, ScimGroup.GROUP_MEMBER);
	}

	public ScimGroupMember(String memberId, Type type, List<ScimGroup.Authority> authorities) {
		this.memberId = memberId;
		this.type = type;
		this.authorities = authorities;
	}
}
