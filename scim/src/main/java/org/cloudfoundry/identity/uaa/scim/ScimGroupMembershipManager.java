package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import java.util.List;
import java.util.Set;

public interface ScimGroupMembershipManager {

	/**
	 * Add a member to a group
	 * @param groupId id of a valid group that already exists.
	 * @param member membership info for enrolling an existing scim object (user or group) in the group
	 * @return
	 * @throws ScimResourceNotFoundException
	 * @throws org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException
	 */
	ScimGroupMember addMember(String groupId, ScimGroupMember member) throws ScimResourceNotFoundException, MemberAlreadyExistsException;

	/**
	 * Retrieve all members of a group
	 * @param groupId
	 * @return
	 * @throws ScimResourceNotFoundException
	 */
	List<ScimGroupMember> getMembers(String groupId) throws ScimResourceNotFoundException;

	/**
	 * Retrieve members that have the specified authority on the group
	 *
	 * @param groupId
	 * @param permission
	 * @return
	 * @throws ScimResourceNotFoundException
	 */
	List<ScimGroupMember> getMembers(String groupId, ScimGroupMember.Role permission) throws ScimResourceNotFoundException;

	/**
	 * Retrieve all groups that the given member belongs to
	 * @param memberId
	 * @param transitive true means indirect/transitive membership is also processed (nested groups)
	 * @return
	 * @throws ScimResourceNotFoundException
	 */
	Set<ScimGroup> getGroupsWithMember(String memberId, boolean transitive) throws ScimResourceNotFoundException;

	/**
	 * Retrieve a particular member's membership details
	 * @param groupId
	 * @param memberId
	 * @return
	 * @throws ScimResourceNotFoundException
	 * @throws org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException
	 */
	ScimGroupMember getMemberById(String groupId, String memberId) throws ScimResourceNotFoundException, MemberNotFoundException;

	/**
	 * Update a particular member's membership details
	 * @param groupId
	 * @param member
	 * @return
	 * @throws ScimResourceNotFoundException
	 * @throws MemberNotFoundException
	 */
	ScimGroupMember updateMember(String groupId, ScimGroupMember member) throws ScimResourceNotFoundException, MemberNotFoundException;

	/**
	 * Replace the members of the given group with the supplied member-list
	 * @param groupId
	 * @param members
	 * @return
	 * @throws ScimResourceNotFoundException
	 */
	List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members) throws ScimResourceNotFoundException;

	/**
	 * Revoke membership of a member
	 * @param groupId
	 * @param memberId
	 * @return
	 * @throws ScimResourceNotFoundException
	 * @throws MemberNotFoundException
	 */
	ScimGroupMember removeMemberById(String groupId, String memberId) throws ScimResourceNotFoundException, MemberNotFoundException;

	/**
	 * Empty the group, i.e revoke the membership of ALL members of a given group
	 * @param groupId
	 * @return
	 * @throws ScimResourceNotFoundException
	 */
	List<ScimGroupMember> removeMembersByGroupId(String groupId) throws ScimResourceNotFoundException;

	/**
	 * Revoke membership of given member from ALL groups
	 * @param memberId
	 * @return
	 * @throws ScimResourceNotFoundException
	 */
	Set<ScimGroup> removeMembersByMemberId(String memberId) throws ScimResourceNotFoundException;

}
