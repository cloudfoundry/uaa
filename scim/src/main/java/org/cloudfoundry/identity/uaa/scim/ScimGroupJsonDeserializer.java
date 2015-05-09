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
package org.cloudfoundry.identity.uaa.scim;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ScimGroupJsonDeserializer extends JsonDeserializer<ScimGroup> {

    @Override
    public ScimGroup deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
        JsonProcessingException {
        ScimGroup group = new ScimGroup();

        Map<ScimGroupMember.Role, List<ScimGroupMember>> roles = new HashMap<ScimGroupMember.Role, List<ScimGroupMember>>();
        for (ScimGroupMember.Role role : ScimGroupMember.Role.values()) {
            roles.put(role, new ArrayList<ScimGroupMember>());
        }
        Set<ScimGroupMember> allMembers = new HashSet<ScimGroupMember>();

        while (jp.nextToken() != JsonToken.END_OBJECT) {
            if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
                String fieldName = jp.getCurrentName();
                jp.nextToken();

                if ("id".equalsIgnoreCase(fieldName)) {
                    group.setId(jp.readValueAs(String.class));
                } else if ("displayname".equalsIgnoreCase(fieldName)) {
                    group.setDisplayName(jp.readValueAs(String.class));
                } else if ("meta".equalsIgnoreCase(fieldName)) {
                    group.setMeta(jp.readValueAs(ScimMeta.class));
                } else if ("schemas".equalsIgnoreCase(fieldName)) {
                    group.setSchemas(jp.readValueAs(String[].class));
                } else {
                    String value = fieldName.substring(0, fieldName.length() - 1);
                    ScimGroupMember.Role role;
                    try {
                        role = ScimGroupMember.Role.valueOf(value.toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        role = null;
                    }
                    if (role != null) {
                        ScimGroupMember[] members = jp.readValueAs(ScimGroupMember[].class);
                        for (ScimGroupMember member : members) {
                            member.setRoles(new ArrayList<ScimGroupMember.Role>());
                        }
                        roles.get(role).addAll(Arrays.asList(members));
                        allMembers.addAll(Arrays.asList(members));
                    }
                }
            }
        }

        for (ScimGroupMember member : allMembers) {
            for (ScimGroupMember.Role role : roles.keySet()) {
                if (roles.get(role).contains(member)) {
                    member.getRoles().add(role);
                }
            }
        }
        group.setMembers(new ArrayList<ScimGroupMember>(allMembers));

        return group;
    }
}
