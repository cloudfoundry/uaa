package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.type.SimpleType;
import org.springframework.util.StringUtils;

import java.io.IOException;
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
    public Set<String> deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
        JsonToken token = jp.getCurrentToken();
        if (token.isScalarValue()) {
            String list = jp.getText();
            list = list.replaceAll("\\s+", ",");
            return new LinkedHashSet<>(Arrays.asList(StringUtils.commaDelimitedListToStringArray(list)));
        }
        return jp.readValueAs(new TypeReference<Set<String>>() {
        });
    }
}