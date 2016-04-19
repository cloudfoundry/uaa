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

import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

public interface ScimGroupMembershipManager extends Queryable<ScimGroupMember> {

    /**
     * Add a member to a group
     *
     * @param groupId id of a valid group that already exists.
     * @param member membership info for enrolling an existing scim object (user
     *            or group) in the group
     * @return
     * @throws ScimResourceNotFoundException
     * @throws org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException
     */
    ScimGroupMember addMember(String groupId, ScimGroupMember member) throws ScimResourceNotFoundException,
                    MemberAlreadyExistsException;

    /**
     * Retrieve all members of a group
     *
     * @param groupId
     * @param filter
     *@param includeEntities  @return
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> getMembers(String groupId, String filter, boolean includeEntities) throws ScimResourceNotFoundException;

    /**
     * Retrieve members that have the specified authority on the group
     *
     * @param groupId
     * @param permission
     * @return
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> getMembers(String groupId, ScimGroupMember.Role permission)
                    throws ScimResourceNotFoundException;

    /**
     * Retrieve all groups that the given member belongs to
     *
     * @param memberId
     * @param transitive true means indirect/transitive membership is also
     *            processed (nested groups)
     * @return
     * @throws ScimResourceNotFoundException
     */
    Set<ScimGroup> getGroupsWithMember(String memberId, boolean transitive) throws ScimResourceNotFoundException;

    /**
     * Retrieve a particular member's membership details
     *
     * @param groupId
     * @param memberId
     * @return
     * @throws ScimResourceNotFoundException
     * @throws MemberNotFoundException
     */
    ScimGroupMember getMemberById(String groupId, String memberId) throws ScimResourceNotFoundException, MemberNotFoundException;

    /**
     * Update a particular member's membership details
     *
     * @param groupId
     * @param member
     * @return
     * @throws ScimResourceNotFoundException
     * @throws MemberNotFoundException
     */
    ScimGroupMember updateMember(String groupId, ScimGroupMember member) throws ScimResourceNotFoundException,
                    MemberNotFoundException;

    /**
     * Replace the members of the given group with the supplied member-list
     *
     * @param groupId
     * @param members
     * @return
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members) throws ScimResourceNotFoundException;

    /**
     * Revoke membership of a member
     *
     * @param groupId
     * @param memberId
     * @return
     * @throws ScimResourceNotFoundException
     * @throws MemberNotFoundException
     */
    ScimGroupMember removeMemberById(String groupId, String memberId) throws ScimResourceNotFoundException,
                    MemberNotFoundException;

    /**
     * Empty the group, i.e revoke the membership of ALL members of a given
     * group
     *
     * @param groupId
     * @return
     * @throws ScimResourceNotFoundException
     */
    List<ScimGroupMember> removeMembersByGroupId(String groupId) throws ScimResourceNotFoundException;

    /**
     * Revoke membership of given member from ALL groups
     *
     * @param memberId
     * @return
     * @throws ScimResourceNotFoundException
     */
    Set<ScimGroup> removeMembersByMemberId(String memberId) throws ScimResourceNotFoundException;

}
