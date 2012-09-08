package org.cloudfoundry.identity.uaa.scim.groups;

import org.cloudfoundry.identity.uaa.scim.ScimResourceNotFoundException;

import java.util.List;

public interface ScimGroupMembershipManager {

	ScimGroupMember addMember(String groupId, ScimGroupMember member) throws ScimResourceNotFoundException, MemberAlreadyExistsException;

	List<ScimGroupMember> getMembers(String groupId) throws ScimResourceNotFoundException;

	ScimGroupMember getMemberById(String groupId, String memberId) throws ScimResourceNotFoundException, MemberNotFoundException;

	List<ScimGroupMember> getAdminMembers(String groupId) throws ScimResourceNotFoundException;

	ScimGroupMember updateMember(String groupId, ScimGroupMember member) throws ScimResourceNotFoundException, MemberNotFoundException;

	List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members) throws ScimResourceNotFoundException;

	ScimGroupMember removeMemberById(String groupId, String memberId) throws ScimResourceNotFoundException, MemberNotFoundException;

	List<ScimGroupMember> removeMembers(String groupId) throws ScimResourceNotFoundException;

}
