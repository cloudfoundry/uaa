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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupMember;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;

public class ScimGroupJsonDeserializer extends JsonDeserializer<ScimGroupInterface> {

    @Override
    public ScimGroupInterface deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
                    JsonProcessingException {

        ScimGroupInterface group = createObject();

        Map<String, Object> context = new HashMap<String, Object>();

        startDeserialization(group, context);

        while (jp.nextToken() != JsonToken.END_OBJECT) {
            if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
                String fieldName = jp.getCurrentName();
                jp.nextToken();
                deserializeField(group, fieldName, jp, context);
            }
        }

        endDeserialization(group, context);

        return group;
    }

    protected ScimGroupInterface createObject()
    {
        return new ScimGroup();
    }

    protected void startDeserialization(ScimGroupInterface group, Map<String, Object> context)
    {
        Map<ScimGroupMemberInterface.Role, List<ScimGroupMember>> roles = new HashMap<ScimGroupMemberInterface.Role, List<ScimGroupMember>>();
        for (ScimGroupMemberInterface.Role role : ScimGroupMemberInterface.Role.values()) {
            roles.put(role, new ArrayList<ScimGroupMember>());
        }
        Set<ScimGroupMember> allMembers = new HashSet<ScimGroupMember>();
        context.put("members", allMembers);
        context.put("roles", roles);
    }

    protected void deserializeField(ScimGroupInterface group, String fieldName, JsonParser jp, Map<String, Object> context) throws JsonProcessingException, IOException
    {
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
            ScimGroupMemberInterface.Role role;
            try {
                role = ScimGroupMemberInterface.Role.valueOf(value.toUpperCase());

                ScimGroupMember[] members = jp.readValueAs(ScimGroupMember[].class);
                for (ScimGroupMemberInterface member : members) {
                    member.setRoles(new ArrayList<ScimGroupMemberInterface.Role>());
                }

                @SuppressWarnings("unchecked")
                Set<ScimGroupMemberInterface> allMembers = (Set<ScimGroupMemberInterface>) context.get("members");

                @SuppressWarnings("unchecked")
                Map<ScimGroupMemberInterface.Role, List<ScimGroupMember>> roles = (Map<ScimGroupMemberInterface.Role, List<ScimGroupMember>>) context.get("roles");

                roles.get(role).addAll(Arrays.asList(members));
                allMembers.addAll(Arrays.asList(members));

            } catch (IllegalArgumentException ex) {
                role = null;
            }
        }
    }

    protected void endDeserialization (ScimGroupInterface group, Map<String, Object> context)
    {
        @SuppressWarnings("unchecked")
        Set<ScimGroupMemberInterface> allMembers = (Set<ScimGroupMemberInterface>) context.get("members");

        @SuppressWarnings("unchecked")
        Map<ScimGroupMemberInterface.Role, List<ScimGroupMember>> roles = (Map<ScimGroupMemberInterface.Role, List<ScimGroupMember>>) context.get("roles");

        for (ScimGroupMemberInterface member : allMembers) {
            for (ScimGroupMemberInterface.Role role : roles.keySet()) {
                if (roles.get(role).contains(member)) {
                    member.getRoles().add(role);
                }
            }
        }
        group.setMembers(new ArrayList<ScimGroupMemberInterface>(allMembers));
    }

}
