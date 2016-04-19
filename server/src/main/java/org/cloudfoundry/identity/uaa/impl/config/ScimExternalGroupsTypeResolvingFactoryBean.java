package org.cloudfoundry.identity.uaa.impl.config;


import org.apache.commons.collections.ListUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
                    externalToInternalMap.put(externalGroup, Arrays.asList(internalGroup));
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
