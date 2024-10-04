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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;

public class UaaAuthenticationSerializer extends JsonSerializer<UaaAuthentication> implements UaaAuthenticationJsonBase {
    @Override
    public void serialize(UaaAuthentication value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        gen.writeStartObject();
        if (value.getDetails() instanceof UaaAuthenticationDetails) {
            gen.writeObjectField(DETAILS, value.getDetails());
        }
        gen.writeObjectField(PRINCIPAL, value.getPrincipal());
        gen.writeObjectField(AUTHORITIES, serializeAuthorites(value.getAuthorities()));
        gen.writeObjectField(EXTERNAL_GROUPS, value.getExternalGroups());
        gen.writeNumberField(EXPIRES_AT, value.getExpiresAt());
        gen.writeNumberField(AUTH_TIME, value.getAuthenticatedTime());
        gen.writeBooleanField(AUTHENTICATED, value.isAuthenticated());
        gen.writeObjectField(PREVIOIUS_LOGIN_SUCCESS_TIME, value.getLastLoginSuccessTime());
        gen.writeObjectField(USER_ATTRIBUTES, value.getUserAttributesAsMap());
        gen.writeObjectField(AUTHENTICATION_METHODS, value.getAuthenticationMethods());
        gen.writeObjectField(AUTHN_CONTEXT_CLASS_REF, value.getAuthContextClassRef());
        gen.writeObjectField(IDP_ID_TOKEN, value.getIdpIdToken());
        gen.writeEndObject();
    }
}
