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
            gen.writePOJOProperty(DETAILS, value.getDetails());
        }
        gen.writePOJOProperty(PRINCIPAL, value.getPrincipal());
        gen.writePOJOProperty(AUTHORITIES, serializeAuthorites(value.getAuthorities()));
        gen.writePOJOProperty(EXTERNAL_GROUPS, value.getExternalGroups());
        gen.writeNumberProperty(EXPIRES_AT, value.getExpiresAt());
        gen.writeNumberProperty(AUTH_TIME, value.getAuthenticatedTime());
        gen.writeBooleanProperty(AUTHENTICATED, value.isAuthenticated());
        gen.writePOJOProperty(PREVIOIUS_LOGIN_SUCCESS_TIME, value.getLastLoginSuccessTime());
        gen.writePOJOProperty(USER_ATTRIBUTES, value.getUserAttributesAsMap());
        gen.writePOJOProperty(AUTHENTICATION_METHODS, value.getAuthenticationMethods());
        gen.writePOJOProperty(AUTHN_CONTEXT_CLASS_REF, value.getAuthContextClassRef());
        gen.writePOJOProperty(IDP_ID_TOKEN, value.getIdpIdToken());
        gen.writeEndObject();
    }
}
