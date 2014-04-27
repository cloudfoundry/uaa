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
package org.cloudfoundry.identity.uaa.scim.json;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.JsonSerializer;
import org.codehaus.jackson.map.SerializerProvider;

public class ScimGroupJsonSerializer extends JsonSerializer<ScimGroupInterface> {
    @Override
    public void serialize(ScimGroupInterface group, JsonGenerator jgen, SerializerProvider provider) throws IOException,
                    JsonProcessingException {

        Map<Object, Object> groupJson = new HashMap<Object, Object>();

        addProperties(group, groupJson);

        jgen.writeObject(groupJson);

    }

    /**
     * Add properties from object to map for conversion into JSON.
     *
     *5 @param group
     * @param groupJson
     */
    protected void addProperties(ScimGroupInterface group, Map<Object, Object> groupJson)
    {
        Map<String, List<ScimGroupMemberInterface>> roles = new HashMap<String, List<ScimGroupMemberInterface>>();
        for (ScimGroupMemberInterface.Role authority : ScimGroupMemberInterface.Role.values()) {
            String role = authority.toString().toLowerCase() + "s";
            roles.put(role, new ArrayList<ScimGroupMemberInterface>());
            if (group.getMembers() != null) {
                for (ScimGroupMemberInterface member : group.getMembers()) {
                    if (member.getRoles().contains(authority)) {
                        roles.get(role).add(member);
                    }
                }
            }
        }

        addNonNull(groupJson, "meta", group.getMeta());
        addNonNull(groupJson, "schemas", group.getSchemas());
        addNonNull(groupJson, "id", group.getId());
        addNonNull(groupJson, "displayName", group.getDisplayName());

        for (Map.Entry<String, List<ScimGroupMemberInterface>> entry : roles.entrySet()) {
            addNonNull(groupJson, entry.getKey(), entry.getValue());
        }
    }

    protected void addNonNull(Map<Object, Object> map, Object key, Object value) {
        if (value == null || (value instanceof Collection && ((Collection<?>) value).isEmpty())) {
            return;
        }
        map.put(key, value);
    }
}
