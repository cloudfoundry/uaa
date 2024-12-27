package org.cloudfoundry.identity.uaa.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

public final class JsonMatcher extends BaseMatcher<String> {

    private final ObjectMapper mapper;

    public static <T> org.hamcrest.Matcher<String> isJsonFile(Class<T> clazz, String fileName) {
        String expectedJson = getResourceAsString(clazz, fileName);
        return new JsonMatcher(expectedJson);
    }

    static org.hamcrest.Matcher<String> isJsonString(String expectedJson) {
        return new JsonMatcher(expectedJson);
    }

    private final String expectedJson;
    private JsonProcessingException jsonException;

    private JsonMatcher(String expectedJson) {
        this.expectedJson = expectedJson;
        this.jsonException = null;
        this.mapper = new ObjectMapper();
    }

    @Override
    public boolean matches(Object actualJson) {
        if (!(actualJson instanceof String)) {
            return false;
        }
        try {
            final JsonNode actualTree = mapper.readTree((String) actualJson);
            final JsonNode expectedTree = mapper.readTree(expectedJson);

            return expectedTree.equals(actualTree);
        } catch (JsonProcessingException e) {
            jsonException = e;
            return false;
        }
    }

    @Override
    public void describeTo(Description description) {
        if (jsonException != null) {
            description.appendText("could not process JSON=<");
            description.appendText(jsonException.getMessage());
            description.appendText(">");
        }
    }
}