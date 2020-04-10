package org.cloudfoundry.identity.uaa.scim.bootstrap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

public class ScimExternalGroupBootstrap implements InitializingBean {

  private static final String GROUP_BY_NAME_AND_ZONE_FILTER =
      "displayName eq \"%s\" and identity_zone_id eq \"%s\"";
  private final ScimGroupProvisioning scimGroupProvisioning;
  private final ScimGroupExternalMembershipManager externalMembershipManager;
  private final Logger logger = LoggerFactory.getLogger(getClass());
  private Map<String, Map<String, List>> externalGroupMaps;
  private boolean addNonExistingGroups = false;

  public ScimExternalGroupBootstrap(
      ScimGroupProvisioning scimGroupProvisioning,
      ScimGroupExternalMembershipManager externalMembershipManager) {
    this.scimGroupProvisioning = scimGroupProvisioning;
    this.externalMembershipManager = externalMembershipManager;
  }

  protected ScimGroupProvisioning getScimGroupProvisioning() {
    return scimGroupProvisioning;
  }

  public boolean isAddNonExistingGroups() {
    return addNonExistingGroups;
  }

  public void setAddNonExistingGroups(boolean addNonExistingGroups) {
    this.addNonExistingGroups = addNonExistingGroups;
  }

  public void setExternalGroupMaps(Map<String, Map<String, List>> externalGroupMaps) {
    this.externalGroupMaps = externalGroupMaps;
  }

  protected ScimGroup addGroup(String groupName) {
    ScimGroup group = new ScimGroup(null, groupName, IdentityZoneHolder.get().getId());
    try {
      return getScimGroupProvisioning().create(group, IdentityZoneHolder.get().getId());
    } catch (ScimResourceAlreadyExistsException x) {
      List<ScimGroup> groups =
          getScimGroupProvisioning()
              .query(
                  String.format(
                      GROUP_BY_NAME_AND_ZONE_FILTER, groupName, IdentityZoneHolder.get().getId()),
                  IdentityZoneHolder.get().getId());
      if (groups != null && groups.size() > 0) {
        return groups.get(0);
      } else {
        throw new RuntimeException("Unable to create or return group with name:" + groupName);
      }
    }
  }

  @Override
  public void afterPropertiesSet() {
    for (String origin : externalGroupMaps.keySet()) {
      Map<String, List> externalGroupMappingsByOrigin = externalGroupMaps.get(origin);
      if (externalGroupMappingsByOrigin != null) {
        for (String externalGroup : externalGroupMappingsByOrigin.keySet()) {
          List<String> internalGroups = externalGroupMappingsByOrigin.get(externalGroup);
          if (internalGroups != null) {
            internalGroups.removeAll(Collections.singleton(null));
            for (String internalGroup : internalGroups) {
              List<ScimGroup> groups =
                  getScimGroupProvisioning()
                      .query(
                          String.format(
                              GROUP_BY_NAME_AND_ZONE_FILTER,
                              internalGroup,
                              IdentityZoneHolder.get().getId()),
                          IdentityZoneHolder.get().getId());

              if (groups == null || groups.size() == 0 && isAddNonExistingGroups()) {
                groups = new ArrayList<>();
                groups.add(addGroup(internalGroup));
              } else if (groups == null || groups.size() == 0 && !isAddNonExistingGroups()) {
                continue;
              }
              addGroupMap(groups.get(0).getId(), externalGroup, origin);
            }
          }
        }
      }
    }
  }

  private void addGroupMap(String groupId, String externalGroup, String origin) {
    ScimGroupExternalMember externalGroupMapping =
        externalMembershipManager.mapExternalGroup(
            groupId, externalGroup, origin, IdentityZoneHolder.get().getId());
    logger.debug("adding external group mapping: " + externalGroupMapping);
  }
}
