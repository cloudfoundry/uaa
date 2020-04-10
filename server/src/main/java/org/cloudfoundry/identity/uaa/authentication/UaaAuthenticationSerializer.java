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
        gen.writeEndObject();
    }
}
