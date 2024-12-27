package org.cloudfoundry.identity.uaa.util;

import com.fasterxml.jackson.core.type.TypeReference;

import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.metrics.UrlGroup;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonUtilsTest {
    private static final String JSON_TEST_OBJECT_STRING = "{\"pattern\":\"/pattern\",\"group\":\"group\",\"limit\":1000,\"category\":\"category\"}";

    @Test
    void writeValueAsString() {
        String testObjectString = JsonUtils.writeValueAsString(getTestObject());
        assertNotNull(testObjectString);
        assertEquals(JSON_TEST_OBJECT_STRING, testObjectString);
    }

    @Test
    void writeValueAsBytes() {
        byte[] testObject = JsonUtils.writeValueAsBytes(getTestObject());
        assertNotNull(testObject);
        assertEquals(JSON_TEST_OBJECT_STRING, new String(testObject));
    }

    @Test
    void testreadValueStringClass() {
        assertNotNull(JsonUtils.readValue(JSON_TEST_OBJECT_STRING, UrlGroup.class));
        assertNull(JsonUtils.readValue((String) null, UrlGroup.class));
    }

    @Test
    void testReadValueByteClass() {
        assertNotNull(JsonUtils.readValue(JSON_TEST_OBJECT_STRING.getBytes(), UrlGroup.class));
        assertNull(JsonUtils.readValue((byte[]) null, UrlGroup.class));
    }

    @Test
    void testReadValueAsMap() {
        final String jsonInput = "{\"prop1\":\"abc\",\"prop2\":{\"prop2a\":\"def\",\"prop2b\":\"ghi\"},\"prop3\":[\"jkl\",\"mno\"]}";
        final Map<String, Object> map = JsonUtils.readValueAsMap(jsonInput);
        Assertions.assertThat(map).isNotNull();
        Assertions.assertThat(map.get("prop1")).isNotNull().isEqualTo("abc");
        Assertions.assertThat(map.get("prop2")).isNotNull().isInstanceOf(Map.class);
        Assertions.assertThat(((Map<String, Object>) map.get("prop2")).get("prop2a")).isNotNull().isEqualTo("def");
        Assertions.assertThat(((Map<String, Object>) map.get("prop2")).get("prop2b")).isNotNull().isEqualTo("ghi");
        Assertions.assertThat(map.get("prop3")).isNotNull().isInstanceOf(List.class);
        Assertions.assertThat((List<String>) map.get("prop3")).containsExactly("jkl", "mno");
    }

    @ParameterizedTest
    @ValueSource(strings = {"{", "}", "{\"prop1\":\"abc\","})
    void testReadValueAsMap_Invalid(final String input) {
        Assertions.assertThatExceptionOfType(JsonUtils.JsonUtilException.class)
                .isThrownBy(() -> JsonUtils.readValueAsMap(input));
    }

    @Test
    void testReadValueBytes() {
        assertNotNull(JsonUtils.readValue(JSON_TEST_OBJECT_STRING.getBytes(), new TypeReference<Map<String, Object>>() {
        }));
        assertNull(JsonUtils.readValue((byte[]) null, new TypeReference<Map<String, Object>>() {
        }));
    }

    @Test
    void testReadValueString() {
        assertNotNull(JsonUtils.readValue(JSON_TEST_OBJECT_STRING, new TypeReference<Map<String, Object>>() {
        }));
        assertNull(JsonUtils.readValue((String) null, new TypeReference<Map<String, Object>>() {
        }));
    }

    @Test
    void testConvertValue() {
        assertNull(JsonUtils.convertValue(null, UrlGroup.class));
    }


    @Test
    void testSerializeExcludingProperties() {
        Map<String, String> groupProperties = JsonUtils.readValue(JSON_TEST_OBJECT_STRING, new TypeReference<>() {
        });
        String resultString = JsonUtils.serializeExcludingProperties(groupProperties, "group", "pattern", "any.limit", "category");
        assertEquals("{\"limit\":\"1000\"}", resultString);
    }

    @Test
    void testSerializeExcludingPropertiesInnerCallFails() {
        Map<String, String> groupProperties = JsonUtils.readValue(JSON_TEST_OBJECT_STRING, new TypeReference<>() {
        });
        assertThrows(JsonUtils.JsonUtilException.class, () ->
                JsonUtils.serializeExcludingProperties(groupProperties, "limit.unknown"));
    }

    @Test
    void testHasLength() {
        assertTrue(JsonUtils.hasLength("X"));
        assertFalse(JsonUtils.hasLength(""));
    }

    @Test
    void testHasText() {
        assertTrue(JsonUtils.hasText("X"));
        assertFalse(JsonUtils.hasText(" "));
    }

    private Object getTestObject() {
        return new UrlGroup().setCategory("category").setGroup("group").setPattern("/pattern").setLimit(1_000L);
    }
}