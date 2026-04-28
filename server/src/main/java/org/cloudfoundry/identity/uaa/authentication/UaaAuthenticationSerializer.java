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

import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

public class UaaAuthenticationSerializer extends ValueSerializer<UaaAuthentication> implements UaaAuthenticationJsonBase {
    @Override
    public void serialize(UaaAuthentication value, JsonGenerator gen, SerializationContext serializers) {
        gen.writeStartObject();
        if (value.getDetails() instanceof UaaAuthenticationDetails) {
            gen.writeObjectProperty(DETAILS, value.getDetails());
        }
        gen.writeObjectProperty(PRINCIPAL, value.getPrincipal());
        gen.writeObjectProperty(AUTHORITIES, serializeAuthorites(value.getAuthorities()));
        gen.writeObjectProperty(EXTERNAL_GROUPS, value.getExternalGroups());
        gen.writeNumberProperty(EXPIRES_AT, value.getExpiresAt());
        gen.writeNumberProperty(AUTH_TIME, value.getAuthenticatedTime());
        gen.writeBooleanProperty(AUTHENTICATED, value.isAuthenticated());
        gen.writeObjectProperty(PREVIOIUS_LOGIN_SUCCESS_TIME, value.getLastLoginSuccessTime());
        gen.writeObjectProperty(USER_ATTRIBUTES, value.getUserAttributesAsMap());
        gen.writeObjectProperty(AUTHENTICATION_METHODS, value.getAuthenticationMethods());
        gen.writeObjectProperty(AUTHN_CONTEXT_CLASS_REF, value.getAuthContextClassRef());
        gen.writeObjectProperty(IDP_ID_TOKEN, value.getIdpIdToken());
        gen.writeEndObject();
    }
}
