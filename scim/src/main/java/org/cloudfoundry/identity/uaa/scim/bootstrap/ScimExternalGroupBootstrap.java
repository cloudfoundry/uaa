/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

public class ScimExternalGroupBootstrap implements InitializingBean {

    private List<Map<String, String>> externalGroupMap;

    private final ScimGroupProvisioning scimGroupProvisioning;

    private final ScimGroupExternalMembershipManager externalMembershipManager;

    private static final String GROUP_BY_NAME_FILTER = "displayName eq '%s'";

    private final Log logger = LogFactory.getLog(getClass());

    public ScimExternalGroupBootstrap(ScimGroupProvisioning scimGroupProvisioning,
                    ScimGroupExternalMembershipManager externalMembershipManager) {
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.externalMembershipManager = externalMembershipManager;
        externalGroupMap = new ArrayList<Map<String, String>>();
    }

    /**
     * Specify the membership info as a list of strings, where each string takes
     * the format -
     * <group-name>|<external-group-names>
     * 
     * external-group-names space separated list of external groups
     * 
     * @param externalGroupMaps
     */
    public void setExternalGroupMap(Set<String> externalGroupMaps) {
        for (String line : externalGroupMaps) {
            String[] fields = line.split("\\|");
            if (fields.length < 2) {
                continue;
            }

            String groupName = fields[0];
            List<ScimGroup> groups = scimGroupProvisioning.query(String.format(GROUP_BY_NAME_FILTER, groupName));

            if (null != groups && groups.size() == 1) {
                String groupId = groups.get(0).getId();
                if (null != fields[1] && fields[1].length() > 0) {
                    String[] externalGroups = fields[1].split(" ");
                    if (null != externalGroups && externalGroups.length > 0) {
                        for (String externalGroup : externalGroups) {
                            if (StringUtils.hasLength(externalGroup.trim())) {
                                externalGroupMap.add(Collections.singletonMap(groupId, externalGroup.trim()));
                            }
                        }
                    }
                }
            }
        }

        logger.debug("external group map: " + externalGroupMap);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        for (Map<String, String> groupMap : externalGroupMap) {
            Entry<String, String> entry = groupMap.entrySet().iterator().next();
            addGroupMap(entry.getKey(), entry.getValue());
        }
    }

    private void addGroupMap(String groupId, String externalGroup) {
        ScimGroupExternalMember externalGroupMapping = externalMembershipManager.mapExternalGroup(groupId,
                        externalGroup);
        logger.debug("adding external group mapping: " + externalGroupMapping);
    }

}
