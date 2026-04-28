package org.cloudfoundry.identity.uaa.test;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import tools.jackson.core.JacksonException;

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
    private JacksonException jsonException;

    private JsonMatcher(String expectedJson) {
        this.expectedJson = expectedJson;
        this.jsonException = null;
        this.mapper = new JsonMapper();
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
        } catch (JacksonException e) {
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