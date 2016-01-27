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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

public class ScimExternalGroupBootstrap implements InitializingBean {

    private List<Map<String, ExternalGroupStruct>> externalGroupMap;
    private Set<String> externalGroupList;

    protected ScimGroupProvisioning getScimGroupProvisioning() {
        return scimGroupProvisioning;
    }

    private final ScimGroupProvisioning scimGroupProvisioning;

    private final ScimGroupExternalMembershipManager externalMembershipManager;

    private static final String GROUP_BY_NAME_FILTER = "displayName eq \"%s\"";

    private final Log logger = LogFactory.getLog(getClass());

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
        externalGroupMap = new ArrayList<>();
    }

    /**
     * Specify the membership info as a list of strings, where each string takes
     * the format -
     * {@code <group-name>|<external-group-names>|origin(optional)}
     * <p>
     * external-group-names space separated list of external groups
     *
     * @param externalGroupMaps
     */
    public void setExternalGroupMap(Set<String> externalGroupMaps) {
        this.externalGroupList = externalGroupMaps;
    }


    protected ScimGroup addGroup(String groupName) {
        ScimGroup group = new ScimGroup(null,groupName,IdentityZoneHolder.get().getId());
        try {
            return getScimGroupProvisioning().create(group);
        } catch (ScimResourceAlreadyExistsException x) {
            List<ScimGroup> groups = getScimGroupProvisioning().query(String.format(GROUP_BY_NAME_FILTER, groupName));
            if (groups!=null && groups.size()>0) {
                return groups.get(0);
            } else {
                throw new RuntimeException("Unable to create or return group with name:"+groupName);
            }
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        for (String line : externalGroupList) {
            String[] fields = line.split("\\|");
            if (fields.length < 2) {
                continue;
            }

            //add the group if it doesn't exist
            String groupName = fields[0];
            List<ScimGroup> groups = getScimGroupProvisioning().query(String.format(GROUP_BY_NAME_FILTER, groupName));
            if (groups == null || groups.size() == 0 && isAddNonExistingGroups()) {
                groups = new ArrayList<>();
                groups.add(addGroup(groupName));
            }


            String origin = OriginKeys.LDAP;
            if (null != groups && groups.size() == 1) {
                String groupId = groups.get(0).getId();
                if (StringUtils.hasText(fields[1])) {
                    String[] externalGroups = fields[1].split(" ");
                    if (fields.length>=3 && StringUtils.hasText(fields[2])) {
                        origin = fields[2];
                    }
                    if (null != externalGroups && externalGroups.length > 0) {
                        for (String externalGroup : externalGroups) {
                            if (StringUtils.hasLength(externalGroup.trim())) {
                                ExternalGroupStruct externalGroupStruct = new ExternalGroupStruct(externalGroup.trim(), origin);
                                externalGroupMap.add(Collections.singletonMap(groupId, externalGroupStruct));
                            }
                        }
                    }
                }

            }
        }


        for (Map<String, ExternalGroupStruct> groupMap : externalGroupMap) {
            Entry<String, ExternalGroupStruct> entry = groupMap.entrySet().iterator().next();
            addGroupMap(entry.getKey(), entry.getValue().externalGroup, entry.getValue().origin);
        }
    }

    private void addGroupMap(String groupId, String externalGroup, String origin) {
        ScimGroupExternalMember externalGroupMapping = externalMembershipManager.mapExternalGroup(groupId, externalGroup, origin);
        logger.debug("adding external group mapping: " + externalGroupMapping);
    }

    private static class ExternalGroupStruct {
        public final String externalGroup;
        public final String origin;

        public ExternalGroupStruct(String externalGroup, String origin) {
            this.externalGroup = externalGroup;
            this.origin = origin;
        }
    }
}
