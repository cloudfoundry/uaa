package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import java.util.List;
import java.util.Set;

public interface ScimGroupMembershipManager {

    /**
     * Add a member to a group
     *
     * @param groupId id of a valid group that already exists.
     * @param member  membership info for enrolling an existing scim object (user
     *                or group) in the group
     */
    ScimGroupMember addMember(
            final String groupId,
            final ScimGroupMember member,
            final String zoneId)
            throws ScimResourceNotFoundException, MemberAlreadyExistsException;

    /**
     * Retrieve all members of a group
     */
    List<ScimGroupMember> getMembers(
            final String groupId,
            final boolean includeEntities,
            final String zoneId)
            throws ScimResourceNotFoundException;

    /**
     * Retrieve all groups that the given member belongs to
     *
     * @param transitive true means indirect/transitive membership is also
     *                   processed (nested groups)
     */
    Set<ScimGroup> getGroupsWithMember(
            final String memberId,
            final boolean transitive,
            final String zoneId) throws ScimResourceNotFoundException;

    /**
     * Retrieve a particular member's membership details
     */
    ScimGroupMember getMemberById(
            final String groupId,
            final String memberId,
            final String zoneId) throws ScimResourceNotFoundException, MemberNotFoundException;

    /**
     * Replace the members of the given group with the supplied member-list
     */
    List<ScimGroupMember> updateOrAddMembers(
            final String groupId,
            final List<ScimGroupMember> members,
            final String zoneId) throws ScimResourceNotFoundException;

    /**
     * Revoke membership of a member
     */
    ScimGroupMember removeMemberById(
            final String groupId,
            final String memberId,
            final String zoneId) throws ScimResourceNotFoundException, MemberNotFoundException;

    /**
     * Empty the group, i.e revoke the membership of ALL members of a given
     * group
     */
    List<ScimGroupMember> removeMembersByGroupId(
            final String groupId,
            final String zoneID) throws ScimResourceNotFoundException;

    /**
     * Revoke membership of given member from ALL groups
     */
    Set<ScimGroup> removeMembersByMemberId(
            final String memberId,
            final String zoneId) throws ScimResourceNotFoundException;

    Set<ScimGroup> removeMembersByMemberId(
            final String memberId,
            final String origin,
            final String zoneId) throws ScimResourceNotFoundException;

    void deleteMembersByOrigin(
            final String origin,
            final String zoneId) throws ScimResourceNotFoundException;

    Set<ScimGroup> getGroupsWithExternalMember(
            final String memberId,
            final String origin,
            final String zoneId) throws ScimResourceNotFoundException;

}
