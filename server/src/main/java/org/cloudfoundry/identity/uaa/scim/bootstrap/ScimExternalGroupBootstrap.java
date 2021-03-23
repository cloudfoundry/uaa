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
package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class ScimExternalGroupBootstrap implements InitializingBean {

    private Map<String, Map<String, List>> externalGroupMaps;

    protected ScimGroupProvisioning getScimGroupProvisioning() {
        return scimGroupProvisioning;
    }

    private final ScimGroupProvisioning scimGroupProvisioning;

    private final ScimGroupExternalMembershipManager externalMembershipManager;

    private static final String GROUP_BY_NAME_AND_ZONE_FILTER = "displayName eq \"%s\" and identity_zone_id eq \"%s\"";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public boolean isAddNonExistingGroups() {
        return addNonExistingGroups;
    }

    public void setAddNonExistingGroups(boolean addNonExistingGroups) {
        this.addNonExistingGroups = addNonExistingGroups;
    }

    private boolean addNonExistingGroups = false;

    public ScimExternalGroupBootstrap(ScimGroupProvisioning scimGroupProvisioning,
                    ScimGroupExternalMembershipManager externalMembershipManager) {
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.externalMembershipManager = externalMembershipManager;
    }

    public void setExternalGroupMaps(Map<String, Map<String, List>> externalGroupMaps) {
        this.externalGroupMaps = externalGroupMaps;
    }


    protected ScimGroup addGroup(String groupName) {
        ScimGroup group = new ScimGroup(null,groupName,IdentityZoneHolder.get().getId());
        try {
            return getScimGroupProvisioning().create(group, IdentityZoneHolder.get().getId());
        } catch (ScimResourceAlreadyExistsException x) {
            List<ScimGroup> groups = getScimGroupProvisioning().query(String.format(GROUP_BY_NAME_AND_ZONE_FILTER, groupName, IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());
            if (groups != null && groups.size() > 0) {
                return groups.get(0);
            } else {
                throw new RuntimeException("Unable to create or return group with name:"+groupName);
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
                            List<ScimGroup> groups = getScimGroupProvisioning().query(String.format(GROUP_BY_NAME_AND_ZONE_FILTER, internalGroup, IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());

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
        ScimGroupExternalMember externalGroupMapping = externalMembershipManager.mapExternalGroup(groupId, externalGroup, origin, IdentityZoneHolder.get().getId());
        logger.debug("adding external group mapping: " + externalGroupMapping);
    }
}
