/*
 * *****************************************************************************
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

import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
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

    private final IdentityZoneManager identityZoneManager;

    public boolean isAddNonExistingGroups() {
        return addNonExistingGroups;
    }

    public void setAddNonExistingGroups(boolean addNonExistingGroups) {
        this.addNonExistingGroups = addNonExistingGroups;
    }

    private boolean addNonExistingGroups;

    public ScimExternalGroupBootstrap(ScimGroupProvisioning scimGroupProvisioning,
            ScimGroupExternalMembershipManager externalMembershipManager, IdentityZoneManager identityZoneManager) {
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.externalMembershipManager = externalMembershipManager;
        this.identityZoneManager = identityZoneManager;
    }

    public void setExternalGroupMaps(Map<String, Map<String, List>> externalGroupMaps) {
        this.externalGroupMaps = externalGroupMaps;
    }


    protected ScimGroup addGroup(String groupName) {
        ScimGroup group = new ScimGroup(null, groupName, identityZoneManager.getCurrentIdentityZoneId());
        try {
            return getScimGroupProvisioning().create(group, identityZoneManager.getCurrentIdentityZoneId());
        } catch (ScimResourceAlreadyExistsException x) {
            List<ScimGroup> groups = getScimGroupProvisioning().query(GROUP_BY_NAME_AND_ZONE_FILTER.formatted(groupName, identityZoneManager.getCurrentIdentityZoneId()), identityZoneManager.getCurrentIdentityZoneId());
            if (groups != null && !groups.isEmpty()) {
                return groups.getFirst();
            } else {
                throw new RuntimeException("Unable to create or return group with name:" + groupName);
            }
        }
    }

    @Override
    public void afterPropertiesSet() {
        for (Map.Entry<String, Map<String, List>> entry : externalGroupMaps.entrySet()) {
            Map<String, List> externalGroupMappingsByOrigin = entry.getValue();
            if (externalGroupMappingsByOrigin != null) {
                for (Map.Entry<String, List> e : externalGroupMappingsByOrigin.entrySet()) {
                    List<String> internalGroups = e.getValue();
                    if (internalGroups != null) {
                        internalGroups.removeAll(Collections.singleton(null));
                        for (String internalGroup : internalGroups) {
                            List<ScimGroup> groups = getScimGroupProvisioning().query(GROUP_BY_NAME_AND_ZONE_FILTER.formatted(internalGroup, identityZoneManager.getCurrentIdentityZoneId()), identityZoneManager.getCurrentIdentityZoneId());

                            if (groups == null || groups.isEmpty() && isAddNonExistingGroups()) {
                                groups = new ArrayList<>();
                                groups.add(addGroup(internalGroup));
                            } else if (groups == null || groups.isEmpty() && !isAddNonExistingGroups()) {
                                continue;
                            }
                            addGroupMap(groups.getFirst().getId(), e.getKey(), entry.getKey());
                        }
                    }
                }
            }
        }
    }

    private void addGroupMap(String groupId, String externalGroup, String origin) {
        ScimGroupExternalMember externalGroupMapping = externalMembershipManager.mapExternalGroup(groupId, externalGroup, origin, identityZoneManager.getCurrentIdentityZoneId());
        logger.debug("adding external group mapping: {}", externalGroupMapping);
    }
}
