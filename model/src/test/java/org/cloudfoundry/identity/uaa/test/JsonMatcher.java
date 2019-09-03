package org.cloudfoundry.identity.uaa.test;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.json.JSONException;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

public class JsonMatcher extends BaseMatcher<String> {

    public static <T> org.hamcrest.Matcher<String> isJsonFile(Class<T> clazz, String fileName) {
        String expectedJson = getResourceAsString(clazz, fileName);
        return new JsonMatcher(expectedJson);
    }

    public static org.hamcrest.Matcher<String> isJsonString(String expectedJson) {
        return new JsonMatcher(expectedJson);
    }

    private String expectedJson;
    private JSONException jsonException;

    private JsonMatcher(String expectedJson) {
        this.expectedJson = expectedJson;
        this.jsonException = null;
    }

    @Override
    public boolean matches(Object actualJson) {
        if (!(actualJson instanceof String)) {
            return false;
        }
        try {
            JSONAssert.assertEquals(expectedJson, (String) actualJson, JSONCompareMode.NON_EXTENSIBLE);
            return true;
        } catch (JSONException e) {
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