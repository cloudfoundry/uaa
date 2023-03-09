/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.commons.collections4.ListUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

import java.util.*;

public class ScimExternalGroupsTypeResolvingFactoryBean {

    public ScimExternalGroupsTypeResolvingFactoryBean(Object o) {
        // Supported list of pipe-delimited internal to external group mappings with space-separated external groups
        if (o instanceof List) {
            Map<String, Map<String, List>> resolvedMap = new HashMap();
            for (String internalToExternalGroupsMapping : ((List<String>) o)) {
                String[] internalExternalOrigin = internalToExternalGroupsMapping.trim().split("\\|");
                if (internalExternalOrigin.length <= 1) {
                    continue;
                }
                String internalGroup = internalExternalOrigin[0];
                String externalGroupsSpaceDelimited = internalExternalOrigin[1];
                String origin = OriginKeys.LDAP;
                if (internalExternalOrigin.length >= 3) {
                    origin = internalExternalOrigin[2];
                }

                String[] externalGroups = externalGroupsSpaceDelimited.trim().split("\\s+");
                Map<String, List> externalToInternalMap = new HashMap<>();
                for (String externalGroup : externalGroups) {
                    externalToInternalMap.put(externalGroup, Collections.singletonList(internalGroup));
                }

                Map<String, List> existingOriginMap = resolvedMap.putIfAbsent(origin, externalToInternalMap);
                if (existingOriginMap != null) {
                    Map<String, List> originMap = resolvedMap.get(origin);

                    Map<String, List> combinedMap = new HashMap<>(originMap);
                    for (Map.Entry<String, List> e : externalToInternalMap.entrySet()) {
                        combinedMap.merge(e.getKey(), e.getValue(), ListUtils::union);
                    }
                    resolvedMap.put(origin, combinedMap);
                }
            }
            externalGroups = resolvedMap;
        } else {
            externalGroups = new HashMap<>((Map<String, Map<String, List>>) o);
        }
    }

    private Map<String, Map<String, List>> externalGroups;

    public Map<String, Map<String, List>> getExternalGroups() {
        return externalGroups;
    }

    public void setExternalGroups(Map<String, Map<String, List>> groups) {
        this.externalGroups = groups;
    }
}
