/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.LAST_LOGON_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;

@JsonDeserialize(using = UserInfoResponse.UserInfoResponsDeserializer.class)
@JsonSerialize(using = UserInfoResponse.UserInfoResponseSerializer.class)
public class UserInfoResponse {
    private static final MultiValueMap<String, Object> EMPTY_MAP = new LinkedMultiValueMap<>();

    MultiValueMap<String, Object> attributes = new LinkedMultiValueMap<>();

    public String getUserId() {
        return (String)getAttributeValue(USER_ID);
    }

    public void setUserId(String userId) {
        setAttributeValue(USER_ID, userId);
    }

    public String getUsername() {
        return (String)getAttributeValue(USER_NAME);
    }

    public void setUsername(String username) {
        setAttributeValue(USER_NAME, username);
    }

    public String getGivenName() {
        return (String)getAttributeValue(GIVEN_NAME);
    }

    public void setGivenName(String givenName) {
        setAttributeValue(GIVEN_NAME, givenName);
    }

    public String getFamilyName() {
        return (String)getAttributeValue(FAMILY_NAME);
    }

    public void setFamilyName(String familyName) {
        setAttributeValue(FAMILY_NAME, familyName);
    }

    @JsonProperty(NAME)
    public String getFullName() {
        return (getGivenName() != null ? getGivenName() : "")
            + (getFamilyName() != null ? " " + getFamilyName() : "");
    }

    public String getEmail() {
        return (String)getAttributeValue(EMAIL);
    }

    public void setEmail(String email) {
        setAttributeValue(EMAIL, email);
    }

    public String getPhoneNumber() {
        return (String)getAttributeValue(PHONE_NUMBER);
    }

    public void setPhoneNumber(String phoneNumber) {
        setAttributeValue(PHONE_NUMBER, phoneNumber);
    }

    public String getSub() {
        return getUserId();
    }

    public void setSub(String sub) {
        setUserId(sub);
    }

    public MultiValueMap<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributeValue(String name, Object value) {
        setAttributeValues(name, Arrays.asList(value));
    }

    public void setAttributeValues(String name, List<Object> value) {
        attributes.put(name, value);
    }

    public List<Object> getAttributeValues(String name) {
        return attributes.get(name);
    }

    public Object getAttributeValue(String name) {
        return attributes.getFirst(name);
    }

    public void addAttributes(MultiValueMap<String,Object> attr) {
        ofNullable(attr).orElse(EMPTY_MAP).entrySet().stream().forEach(
            e -> setAttributeValues(e.getKey(), e.getValue())
        );
    }

    public Long getLastLogonSuccess() {
        return (Long) getAttributeValue(LAST_LOGON_TIME);
    }

    public void setLastLogonSuccess(Long lastLogonSuccess) {
        setAttributeValue(LAST_LOGON_TIME, lastLogonSuccess);
    }


    public static class UserInfoResponseSerializer extends JsonSerializer<UserInfoResponse> {
        @Override
        public void serialize(UserInfoResponse object, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeStartObject();
            for (Map.Entry<String, List<Object>> entry : object.getAttributes().entrySet()) {
                String key = entry.getKey();
                List<Object> value = entry.getValue();
                switch (key) {
                    //single value fields
                    case USER_ID:
                        //integration tests expect both user_id and sub to be present
                        gen.writeFieldName(USER_ID);
                        gen.writeObject(object.getUserId());
                        key = SUB; //use proper claim name
                    case USER_NAME:
                    case GIVEN_NAME:
                    case FAMILY_NAME:
                    case PHONE_NUMBER:
                    case EMAIL: {
                        gen.writeFieldName(key);
                        if (value == null || value.size() == 0) {
                            gen.writeNull();
                        } else {
                            //ensure that type error happens early
                            String svalue = (String)value.get(0);
                            gen.writeObject(svalue);
                        }
                        break;
                    }
                    case LAST_LOGON_TIME:
                        gen.writeFieldName(key);
                        gen.writeObject(value.get(0));
                        break;
                    //multi value fields
                    default:
                        gen.writeFieldName(key);
                        gen.writeObject(value);
                        break;
                }
            }

            gen.writeFieldName(NAME);
            gen.writeObject(object.getFullName());
            gen.writeEndObject();
        }
    }

    public static class UserInfoResponsDeserializer extends JsonDeserializer<UserInfoResponse> {
        @Override
        public UserInfoResponse deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
            JsonNode node = JsonUtils.readTree(p);
            Map<String, Object> map = JsonUtils.getNodeAsMap(node);
            UserInfoResponse response = new UserInfoResponse();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                switch (key) {
                    case NAME:
                        break; //we don't store this one
                    //single value fields
                    case SUB:
                        key = USER_ID; //use proper attribute name
                    case USER_NAME:
                    case GIVEN_NAME:
                    case FAMILY_NAME:
                    case PHONE_NUMBER:
                    case EMAIL: {
                        response.setAttributeValue(key, value);
                        break;
                    }
                    case LAST_LOGON_TIME:
                        Long longValue = value.getClass() == Long.class ? (Long) value : (Long) ((Integer) value).longValue();
                        response.setAttributeValue(key, longValue);
                        break;
                    //multi value fields
                    default:
                        if (value instanceof List) {
                            response.setAttributeValues(key, (List) value);
                        } else {
                            response.setAttributeValue(key, value);
                        }
                        break;
                }
            }
            return response;
        }
    }
}
