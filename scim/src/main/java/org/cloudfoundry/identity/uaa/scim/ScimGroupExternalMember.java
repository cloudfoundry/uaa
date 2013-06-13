package org.cloudfoundry.identity.uaa.scim;

import org.codehaus.jackson.map.annotate.JsonSerialize;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class ScimGroupExternalMember extends ScimCore {

	private String groupId;

	private String externalGroup;

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

	@Override
	public String toString() {
		return String
				.format("(Group id: %s, created: %s, modified: %s, version: %s, externalGroups: %s)",
						getId(), getMeta().getCreated(), getMeta().getLastModified(), getVersion(),
						externalGroup);
	}
}
