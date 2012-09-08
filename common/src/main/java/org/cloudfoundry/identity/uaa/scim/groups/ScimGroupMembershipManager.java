package org.cloudfoundry.identity.uaa.scim.groups;

import java.util.List;

public interface ScimGroupMembershipManager {

    ScimGroupMember addMember (String groupId, ScimGroupMember member) throws GroupNotFoundException, MemberAlreadyExistsException;

    List<ScimGroupMember> getMembers (String groupId) throws GroupNotFoundException;

    ScimGroupMember getMemberById (String groupId, String memberId) throws GroupNotFoundException, MemberNotFoundException;

    List<ScimGroupMember> getAdminMembers (String groupId) throws GroupNotFoundException;

    ScimGroupMember updateMember (String groupId, ScimGroupMember member) throws GroupNotFoundException, MemberNotFoundException;

    List<ScimGroupMember> updateOrAddMembers (String groupId, List<ScimGroupMember> members) throws GroupNotFoundException;

    ScimGroupMember removeMemberById (String groupId, String memberId) throws GroupNotFoundException, MemberNotFoundException;

    List<ScimGroupMember> removeMembers (String groupId) throws GroupNotFoundException;

}
