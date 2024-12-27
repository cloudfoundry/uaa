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
package org.cloudfoundry.identity.uaa.scim.impl;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.JsonDateDeserializer;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

public class ScimUserJsonDeserializer extends JsonDeserializer<ScimUser> {
    @Override
    public ScimUser deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        ScimUser user = new ScimUser();
        while (jp.nextToken() != JsonToken.END_OBJECT) {
            if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
                String fieldName = jp.getCurrentName();
                jp.nextToken();

                if ("id".equalsIgnoreCase(fieldName)) {
                    user.setId(jp.readValueAs(String.class));
                } else if ("userName".equalsIgnoreCase(fieldName)) {
                    user.setUserName(jp.readValueAs(String.class));
                } else if ("externalId".equalsIgnoreCase(fieldName)) {
                    user.setExternalId(jp.readValueAs(String.class));
                } else if ("meta".equalsIgnoreCase(fieldName)) {
                    user.setMeta(jp.readValueAs(ScimMeta.class));
                } else if ("schemas".equalsIgnoreCase(fieldName)) {
                    user.setSchemas(jp.readValueAs(String[].class));
                } else if ("userType".equalsIgnoreCase(fieldName)) {
                    user.setUserType(jp.readValueAs(String.class));
                } else if ("title".equalsIgnoreCase(fieldName)) {
                    user.setTitle(jp.readValueAs(String.class));
                } else if ("timezone".equalsIgnoreCase(fieldName)) {
                    user.setTimezone(jp.readValueAs(String.class));
                } else if ("profileUrl".equalsIgnoreCase(fieldName)) {
                    user.setProfileUrl(jp.readValueAs(String.class));
                } else if ("preferredLanguage".equalsIgnoreCase(fieldName)) {
                    user.setPreferredLanguage(jp.readValueAs(String.class));
                } else if ("phoneNumbers".equalsIgnoreCase(fieldName)) {
                    ScimUser.PhoneNumber[] phoneNumbers = jp.readValueAs(ScimUser.PhoneNumber[].class);
                    if (phoneNumbers != null) {
                        user.setPhoneNumbers(Arrays.asList(phoneNumbers));
                    } else {
                        user.setPhoneNumbers(new ArrayList<>());
                    }
                } else if ("password".equalsIgnoreCase(fieldName)) {
                    user.setPassword(jp.readValueAs(String.class));
                } else if ("nickname".equalsIgnoreCase(fieldName)) {
                    user.setNickName(jp.readValueAs(String.class));
                } else if ("name".equalsIgnoreCase(fieldName)) {
                    user.setName(jp.readValueAs(ScimUser.Name.class));
                } else if ("locale".equalsIgnoreCase(fieldName)) {
                    user.setLocale(jp.readValueAs(String.class));
                } else if ("emails".equalsIgnoreCase(fieldName)) {
                    user.setEmails(Arrays.asList(jp.readValueAs(ScimUser.Email[].class)));
                } else if ("groups".equalsIgnoreCase(fieldName)) {
                    user.setGroups(Arrays.asList(jp.readValueAs(ScimUser.Group[].class)));
                } else if ("displayName".equalsIgnoreCase(fieldName)) {
                    user.setDisplayName(jp.readValueAs(String.class));
                } else if ("active".equalsIgnoreCase(fieldName)) {
                    user.setActive(jp.readValueAs(Boolean.class));
                } else if ("verified".equalsIgnoreCase(fieldName)) {
                    user.setVerified(jp.readValueAs(Boolean.class));
                } else if (OriginKeys.ORIGIN.equalsIgnoreCase(fieldName)) {
                    user.setOrigin(jp.readValueAs(String.class));
                } else if ("zoneId".equalsIgnoreCase(fieldName)) {
                    user.setZoneId(jp.readValueAs(String.class));
                } else if ("aliasId".equalsIgnoreCase(fieldName)) {
                    user.setAliasId(jp.readValueAs(String.class));
                } else if ("aliasZid".equalsIgnoreCase(fieldName)) {
                    user.setAliasZid(jp.readValueAs(String.class));
                } else if ("salt".equalsIgnoreCase(fieldName)) {
                    user.setSalt(jp.readValueAs(String.class));
                } else if ("passwordLastModified".equalsIgnoreCase(fieldName)) {
                    if (jp.getValueAsString() != null) {
                        user.setPasswordLastModified(JsonDateDeserializer.getDate(jp.getValueAsString(), jp.getCurrentLocation()));
                    }
                } else if ("approvals".equalsIgnoreCase(fieldName)) {
                    user.setApprovals(new HashSet<>(Arrays.asList(jp.readValueAs(Approval[].class))));
                } else if ("lastLogonTime".equalsIgnoreCase(fieldName)) {
                    if (jp.getValueAsString() != null) {
                        user.setLastLogonTime(jp.getValueAsLong());
                    }
                } else if ("previousLogonTime".equalsIgnoreCase(fieldName)) {
                    if (jp.getValueAsString() != null) {
                        user.setPreviousLogonTime(jp.getValueAsLong());
                    }
                } else {
                    throw new UnrecognizedPropertyException("unrecognized field", jp.getCurrentLocation(),
                            ScimUser.class, fieldName, Collections.emptySet());
                }
            }
        }
        return user;
    }

}
