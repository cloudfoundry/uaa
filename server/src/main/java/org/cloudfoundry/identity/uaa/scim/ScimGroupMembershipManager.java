/*******************************************************************************
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

import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import java.util.List;
import java.util.Set;

public interface ScimGroupMembershipManager  {

    /**
     * Add a member to a group
     *
     * @param groupId id of a valid group that already exists.
     * @param member  membership info for enrolling an existing scim object (user
     *                or group) in the group
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     * @throws org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException
     */
    ScimGroupMember addMember(String groupId, ScimGroupMember member, final String zoneId)
        throws ScimResourceNotFoundException, MemberAlreadyExistsException;

    /**
     * Retrieve all members of a group
     *
     * @param groupId
     * @param includeEntities @return
     * @param zoneId
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> getMembers(String groupId, boolean includeEntities, String zoneId)
        throws ScimResourceNotFoundException;

    /**
     * Retrieve members that have the specified authority on the group
     *
     * @param groupId
     * @param permission
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> getMembers(String groupId, ScimGroupMember.Role permission, final String zoneId)
        throws ScimResourceNotFoundException;

    /**
     * Retrieve all groups that the given member belongs to
     *
     * @param memberId
     * @param transitive true means indirect/transitive membership is also
     *                   processed (nested groups)
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     */
    Set<ScimGroup> getGroupsWithMember(String memberId, boolean transitive, String zoneId) throws ScimResourceNotFoundException;

    /**
     * Retrieve a particular member's membership details
     *
     * @param groupId
     * @param memberId
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     * @throws MemberNotFoundException
     */
    ScimGroupMember getMemberById(String groupId, String memberId, String zoneId) throws ScimResourceNotFoundException, MemberNotFoundException;

    /**
     * Update a particular member's membership details
     *
     * @param groupId
     * @param member
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     * @throws MemberNotFoundException
     */
    ScimGroupMember updateMember(String groupId, ScimGroupMember member, final String zoneId) throws ScimResourceNotFoundException,
        MemberNotFoundException;

    /**
     * Replace the members of the given group with the supplied member-list
     *
     * @param groupId
     * @param members
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members, String zoneId) throws ScimResourceNotFoundException;

    /**
     * Revoke membership of a member
     *
     * @param groupId
     * @param memberId
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     * @throws MemberNotFoundException
     */
    ScimGroupMember removeMemberById(String groupId, String memberId, final String zoneId) throws ScimResourceNotFoundException,
        MemberNotFoundException;

    /**
     * Empty the group, i.e revoke the membership of ALL members of a given
     * group
     *
     * @param groupId
     * @param zoneID
     * @return
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> removeMembersByGroupId(String groupId, final String zoneID) throws ScimResourceNotFoundException;

    /**
     * Revoke membership of given member from ALL groups
     *
     * @param memberId
     * @param zoneId
     * @return
     * @throws ScimResourceNotFoundException
     */
    Set<ScimGroup> removeMembersByMemberId(String memberId, final String zoneId) throws ScimResourceNotFoundException;

    Set<ScimGroup> removeMembersByMemberId(String memberId, String origin, final String zoneId) throws ScimResourceNotFoundException;

    void deleteMembersByOrigin(String origin, String zoneId) throws ScimResourceNotFoundException;

}
