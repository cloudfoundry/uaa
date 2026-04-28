package org.cloudfoundry.identity.uaa.client;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JavaType;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.type.SimpleType;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Moved class Jackson2ArrayOrStringDeserializer implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 */
@SuppressWarnings("serial")
public class Jackson2ArrayOrStringDeserializer extends StdDeserializer<Set<String>> {

    public Jackson2ArrayOrStringDeserializer() {
        super(Set.class);
    }

    @Override
    public JavaType getValueType() {
        return SimpleType.construct(String.class);
    }

    @Override
    public Set<String> deserialize(JsonParser jp, DeserializationContext ctxt) {
        JsonToken token = jp.getCurrentToken();
        if (token.isScalarValue()) {
            String list = jp.getString();
            list = list.replaceAll("\\s+", ",");
            return new LinkedHashSet<>(Arrays.asList(StringUtils.commaDelimitedListToStringArray(list)));
        }
        return jp.readValueAs(new TypeReference<Set<String>>() {
        });
    }
}