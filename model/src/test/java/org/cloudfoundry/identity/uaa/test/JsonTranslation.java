package org.cloudfoundry.identity.uaa.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.cloudfoundry.identity.uaa.test.JsonMatcher.isJsonFile;
import static org.cloudfoundry.identity.uaa.test.JsonMatcher.isJsonString;
import static org.cloudfoundry.identity.uaa.test.JsonTranslation.WithAllNullFields.EXPECT_EMPTY_JSON;
import static org.cloudfoundry.identity.uaa.test.JsonTranslation.WithAllNullFields.EXPECT_NULLS_IN_JSON;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public abstract class JsonTranslation<T> {

    private T subject;
    private Class<T> subjectClass;
    private WithAllNullFields withAllNullFields;

    public enum WithAllNullFields {
        DONT_CHECK,
        EXPECT_EMPTY_JSON,
        EXPECT_NULLS_IN_JSON
    }

    private ObjectMapper objectMapper;
    private String jsonFileName;

    protected void setUp(
            final T subject,
            final Class<T> clazz) {
        this.setUp(subject, clazz, WithAllNullFields.EXPECT_NULLS_IN_JSON);
    }

    protected void setUp(
            final T subject,
            final Class<T> clazz,
            final WithAllNullFields withAllNullFields) {
        this.subject = subject;
        this.subjectClass = clazz;
        this.withAllNullFields = withAllNullFields;

        this.jsonFileName = subjectClass.getSimpleName() + ".json";
        this.objectMapper = new ObjectMapper();
    }

    protected ObjectMapper getObjectMapper() {
        return this.objectMapper;
    }

    private void validate() {
        assertThat(String.format("subject cannot be null, did you forget to call %s::setUp?", JsonTranslation.class.getSimpleName()),
                this.subject, not(nullValue()));
        assertThat(String.format("subjectClass cannot be null, did you forget to call %s::setUp?", JsonTranslation.class.getSimpleName()),
                this.subjectClass, not(nullValue()));
    }

    @Test
    void toJson() throws JsonProcessingException {
        validate();
        assertThat(String.format("file <%s/%s> must exist on classpath", subjectClass.getPackage().getName().replace(".", "/"), jsonFileName),
                subjectClass.getResourceAsStream(jsonFileName),
                notNullValue());

        String actual = objectMapper.writeValueAsString(subject);

        assertThat(actual, isJsonFile(subjectClass, jsonFileName));
    }

    @Test
    void fromJson() throws IOException {
        validate();
        assertThat(String.format("file <%s/%s> must exist on classpath", subjectClass.getPackage().getName().replace(".", "/"), jsonFileName),
                subjectClass.getResourceAsStream(jsonFileName),
                notNullValue());

        String json = getResourceAsString(subjectClass, jsonFileName);

        T actual = objectMapper.readValue(json, subjectClass);

        assertThat(actual, is(subject));
    }

    @Test
    void withNullFields_checkIsEmptyJson() throws IllegalAccessException, InstantiationException, JsonProcessingException {
        assumeTrue(EXPECT_EMPTY_JSON.equals(withAllNullFields),
                String.format("To configure this test, use %s instead of %s", EXPECT_EMPTY_JSON, withAllNullFields));
        validate();

        String actual = objectMapper.writeValueAsString(subjectClass.newInstance());

        assertThat(actual, isJsonString("{}"));
    }

    @Test
    void withNullFields_compareToFile() throws JsonProcessingException, IllegalAccessException, InstantiationException {
        assumeTrue(EXPECT_NULLS_IN_JSON.equals(withAllNullFields),
                String.format("To configure this test, use %s instead of %s", EXPECT_NULLS_IN_JSON, withAllNullFields));
        validate();

        String fileName = subjectClass.getSimpleName() + "-nulls.json";

        assertThat(String.format("file <%s/%s> must exist on classpath, or choose a different %s", subjectClass.getPackage().getName().replace(".", "/"), fileName, WithAllNullFields.class.getSimpleName()),
                subjectClass.getResourceAsStream(fileName),
                notNullValue());

        String actual = objectMapper.writeValueAsString(subjectClass.newInstance());
        assertThat(actual, isJsonFile(this.getClass(), fileName));
    }
}
