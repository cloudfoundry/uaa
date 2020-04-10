package org.cloudfoundry.identity.uaa.scim;

import java.util.List;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

public interface ScimGroupExternalMembershipManager {

  ScimGroupExternalMember mapExternalGroup(
      String groupId, String externalGroup, String origin, final String zoneId)
      throws ScimResourceNotFoundException, MemberAlreadyExistsException;

  ScimGroupExternalMember unmapExternalGroup(
      String groupId, String externalGroup, String origin, final String zoneId)
      throws ScimResourceNotFoundException;

  List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(
      String groupId, String origin, final String zoneId) throws ScimResourceNotFoundException;

  List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(
      String externalGroup, String origin, final String zoneId)
      throws ScimResourceNotFoundException;

  List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(
      String groupName, String origin, final String zoneId) throws ScimResourceNotFoundException;

  List<ScimGroupExternalMember> getExternalGroupMappings(String zoneId)
      throws ScimResourceNotFoundException;

  void unmapAll(String groupId, final String zoneId) throws ScimResourceNotFoundException;
}
