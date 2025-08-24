package org.cloudfoundry.identity.uaa.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.HamcrestCondition.matching;
import static org.cloudfoundry.identity.uaa.test.JsonMatcher.isJsonFile;
import static org.cloudfoundry.identity.uaa.test.JsonMatcher.isJsonString;
import static org.cloudfoundry.identity.uaa.test.JsonTranslation.WithAllNullFields.EXPECT_EMPTY_JSON;
import static org.cloudfoundry.identity.uaa.test.JsonTranslation.WithAllNullFields.EXPECT_NULLS_IN_JSON;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
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
        assertThat(this.subject).as("subject cannot be null, did you forget to call %s::setUp?".formatted(JsonTranslation.class.getSimpleName())).isNotNull();
        assertThat(this.subjectClass).as("subjectClass cannot be null, did you forget to call %s::setUp?".formatted(JsonTranslation.class.getSimpleName())).isNotNull();
    }

    @Test
    void toJson() throws JsonProcessingException {
        validate();
        assertThat(subjectClass.getResourceAsStream(jsonFileName)).as("file <%s/%s> must exist on classpath".formatted(subjectClass.getPackage().getName().replace(".", "/"), jsonFileName)).isNotNull();

        String actual = objectMapper.writeValueAsString(subject);

        assertThat(actual).is(matching(isJsonFile(subjectClass, jsonFileName)));
    }

    @Test
    void fromJson() throws IOException {
        validate();
        assertThat(subjectClass.getResourceAsStream(jsonFileName)).as("file <%s/%s> must exist on classpath".formatted(subjectClass.getPackage().getName().replace(".", "/"), jsonFileName)).isNotNull();

        String json = getResourceAsString(subjectClass, jsonFileName);

        T actual = objectMapper.readValue(json, subjectClass);

        assertThat(actual).isEqualTo(subject);
    }

    @Test
    void withNullFields_checkIsEmptyJson() throws IllegalAccessException, InstantiationException, JsonProcessingException {
        assumeTrue(EXPECT_EMPTY_JSON.equals(withAllNullFields),
                "To configure this test, use %s instead of %s".formatted(EXPECT_EMPTY_JSON, withAllNullFields));
        validate();

        String actual = objectMapper.writeValueAsString(subjectClass.newInstance());
        assertThat(actual).is(matching(isJsonString("{}")));
    }

    @Test
    void withNullFields_compareToFile() throws JsonProcessingException, IllegalAccessException, InstantiationException {
        assumeTrue(EXPECT_NULLS_IN_JSON.equals(withAllNullFields),
                "To configure this test, use %s instead of %s".formatted(EXPECT_NULLS_IN_JSON, withAllNullFields));
        validate();

        String fileName = subjectClass.getSimpleName() + "-nulls.json";

        assertThat(subjectClass.getResourceAsStream(fileName)).as("file <%s/%s> must exist on classpath, or choose a different %s".formatted(subjectClass.getPackage().getName().replace(".", "/"), fileName, WithAllNullFields.class.getSimpleName())).isNotNull();

        String actual = objectMapper.writeValueAsString(subjectClass.newInstance());
        assertThat(actual).is(matching(isJsonFile(this.getClass(), fileName)));
    }
}
