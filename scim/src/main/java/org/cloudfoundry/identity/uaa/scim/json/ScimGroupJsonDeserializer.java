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

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupMember;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

public class ScimGroupJsonDeserializer extends JsonDeserializer<ScimGroupInterface> {

    @Override
    public ScimGroupInterface deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
                    JsonProcessingException {


        ScimGroup group = new ScimGroup();

        Map<ScimGroupMemberInterface.Role, List<ScimGroupMember>> roles = new HashMap<ScimGroupMemberInterface.Role, List<ScimGroupMember>>();
        for (ScimGroupMemberInterface.Role role : ScimGroupMemberInterface.Role.values()) {
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
                    ScimGroupMemberInterface.Role role;
                    try {
                        role = ScimGroupMemberInterface.Role.valueOf(value.toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        role = null;
                    }
                    if (role != null) {
                        ScimGroupMember[] members = jp.readValueAs(ScimGroupMember[].class);
                        for (ScimGroupMemberInterface member : members) {
                            member.setRoles(new ArrayList<ScimGroupMemberInterface.Role>());
                        }
                        roles.get(role).addAll(Arrays.asList(members));
                        allMembers.addAll(Arrays.asList(members));
                    }
                }
            }
        }

        for (ScimGroupMemberInterface member : allMembers) {
            for (ScimGroupMemberInterface.Role role : roles.keySet()) {
                if (roles.get(role).contains(member)) {
                    member.getRoles().add(role);
                }
            }
        }
        group.setMembers(new ArrayList<ScimGroupMemberInterface>(allMembers));

        return group;
    }
}
