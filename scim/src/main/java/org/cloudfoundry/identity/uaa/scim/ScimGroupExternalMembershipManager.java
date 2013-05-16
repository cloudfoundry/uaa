package org.cloudfoundry.identity.uaa.scim;

import java.util.List;

import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

public interface ScimGroupExternalMembershipManager {

	public ScimGroupExternalMember mapExternalGroup(final String groupId, final String externalGroup) throws ScimResourceNotFoundException, MemberAlreadyExistsException;

	public List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(final String groupId) throws ScimResourceNotFoundException;

	public List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(final String externalGroup) throws ScimResourceNotFoundException;

	public List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(final String groupName) throws ScimResourceNotFoundException;
}
