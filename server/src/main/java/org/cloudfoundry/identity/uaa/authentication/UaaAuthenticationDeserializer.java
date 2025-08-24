/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;

public class UaaAuthenticationDeserializer extends JsonDeserializer<UaaAuthentication> implements UaaAuthenticationJsonBase {
    @Override
    public UaaAuthentication deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        UaaAuthenticationDetails details = null;
        UaaPrincipal princpal = null;
        List<? extends GrantedAuthority> authorities = emptyList();
        Set<String> externalGroups = emptySet();
        Set<String> authenticationMethods = emptySet();
        Set<String> authNContextClassRef = null;
        long expiresAt = -1;
        long authenticatedTime = -1;
        boolean authenticated = false;
        long previousLoginSuccessTime = -1;
        String idpIdToken = null;
        Map<String, List<String>> userAttributes = emptyMap();
        while (jp.nextToken() != JsonToken.END_OBJECT) {
            if (jp.getCurrentToken() == JsonToken.FIELD_NAME) {
                String fieldName = jp.getCurrentName();
                jp.nextToken();
                if (NULL_STRING.equals(jp.getText())) {
                    //do nothing
                } else if (DETAILS.equals(fieldName)) {
                    details = jp.readValueAs(UaaAuthenticationDetails.class);
                } else if (PRINCIPAL.equals(fieldName)) {
                    princpal = jp.readValueAs(UaaPrincipal.class);
                } else if (AUTHORITIES.equals(fieldName)) {
                    authorities = deserializeAuthorites(jp.readValueAs(new TypeReference<List<String>>(){
                    }));
                } else if (EXTERNAL_GROUPS.equals(fieldName)) {
                    externalGroups = jp.readValueAs(new TypeReference<Set<String>>(){
                    });
                } else if (EXPIRES_AT.equals(fieldName)) {
                    expiresAt = jp.getLongValue();
                } else if (AUTH_TIME.equals(fieldName)) {
                    authenticatedTime = jp.getLongValue();
                } else if (AUTHENTICATED.equals(fieldName)) {
                    authenticated = jp.getBooleanValue();
                } else if (USER_ATTRIBUTES.equals(fieldName)) {
                    userAttributes = jp.readValueAs(new TypeReference<Map<String, List<String>>>() {
                    });
                } else if (AUTHENTICATION_METHODS.equals(fieldName)) {
                    authenticationMethods = jp.readValueAs(new TypeReference<Set<String>>() {
                    });
                } else if (AUTHN_CONTEXT_CLASS_REF.equals(fieldName)) {
                    authNContextClassRef = jp.readValueAs(new TypeReference<Set<String>>() {
                    });
                } else if (PREVIOIUS_LOGIN_SUCCESS_TIME.equals(fieldName)) {
                    previousLoginSuccessTime = jp.getLongValue();
                } else if (IDP_ID_TOKEN.equals(fieldName)) {
                    idpIdToken = jp.readValueAs(new TypeReference<String>() {
                    });
                }
            }
        }
        if (princpal == null) {
            throw new JsonMappingException("Missing " + UaaPrincipal.class.getName());
        }
        UaaAuthentication uaaAuthentication = new UaaAuthentication(princpal,
                null,
                authorities,
                externalGroups,
                userAttributes,
                details,
                authenticated,
                authenticatedTime,
                expiresAt);
        uaaAuthentication.setAuthenticationMethods(authenticationMethods);
        uaaAuthentication.setAuthContextClassRef(authNContextClassRef);
        uaaAuthentication.setLastLoginSuccessTime(previousLoginSuccessTime);
        uaaAuthentication.setIdpIdToken(idpIdToken);
        return uaaAuthentication;
    }
}
