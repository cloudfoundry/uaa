package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.ser.std.StdSerializer;

import java.util.Map.Entry;

import tools.jackson.databind.SerializationContext;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 exceptions
 */
public class OAuth2ExceptionJackson2Serializer extends StdSerializer<OAuth2Exception> {

    public OAuth2ExceptionJackson2Serializer(Class vc) {
        super(vc);
    }

    public OAuth2ExceptionJackson2Serializer() {
        super(OAuth2Exception.class);
    }

    @Override
    public void serialize(OAuth2Exception value, JsonGenerator jgen, SerializationContext provider) {
        jgen.writeStartObject();
        jgen.writeStringProperty(OAuth2Exception.ERROR, value.getOAuth2ErrorCode());
        jgen.writeStringProperty(OAuth2Exception.DESCRIPTION, value.getMessage());
        if (value.getAdditionalInformation() != null) {
            for (Entry<String, String> entry : value.getAdditionalInformation().entrySet()) {
                String key = entry.getKey();
                String add = entry.getValue();
                jgen.writeStringProperty(key, add);
            }
        }
        jgen.writeEndObject();
    }

}
