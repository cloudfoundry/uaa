package org.cloudfoundry.identity.uaa.impl.config;


import org.apache.commons.collections.ListUtils;

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
                String[] internalExternalOrigin = internalToExternalGroupsMapping.split("\\|");
                String internalGroup = internalExternalOrigin[0];
                String externalGroupsSpaceDelimited = internalExternalOrigin[1];
                String origin = "ldap";
                if (internalExternalOrigin.length >= 3) {
                    origin = internalExternalOrigin[2];
                }

                String[] externalGroups = externalGroupsSpaceDelimited.split("\\s+");
                Map<String, List> externalToInternalMap = new HashMap<>();
                for (String externalGroup : externalGroups) {
                    List<String> existingMapValue = externalToInternalMap.putIfAbsent(externalGroup, Arrays.asList(internalGroup));
                    if (existingMapValue != null) {
                        List<String> externalGroupMappingValues = externalToInternalMap.get(externalGroup);
                        externalGroupMappingValues.add(internalGroup);
                        externalToInternalMap.put(externalGroup, externalGroupMappingValues);
                    }
                }

                Map<String, List> existingOriginMap = resolvedMap.putIfAbsent(origin, externalToInternalMap);
                if (existingOriginMap != null) {
                    Map<String, List> originMap = resolvedMap.get(origin);

                    Map<String, List> combinedMap = new HashMap<>(originMap);
                    for (Map.Entry<String, List> e : externalToInternalMap.entrySet())
                        combinedMap.merge(e.getKey(), e.getValue(), ListUtils::union);
                    externalToInternalMap.forEach((k, v) -> combinedMap.merge(k, v, ListUtils::union));

                    resolvedMap.put(origin, combinedMap);
                }
            }
            externalGroups = resolvedMap;
        } else {
            externalGroups = ((Map<String, Map<String, List>>) o);
            System.out.println("s");
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
