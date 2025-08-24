package org.cloudfoundry.identity.uaa.util;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.identity.uaa.metrics.UrlGroup;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonUtilsTest {
    private static final String JSON_TEST_OBJECT_STRING = "{\"pattern\":\"/pattern\",\"group\":\"group\",\"limit\":1000,\"category\":\"category\"}";

    @Test
    void writeValueAsString() {
        String testObjectString = JsonUtils.writeValueAsString(getTestObject());
        assertThat(testObjectString).isEqualTo(JSON_TEST_OBJECT_STRING);
    }

    @Test
    void writeValueAsBytes() {
        byte[] testObject = JsonUtils.writeValueAsBytes(getTestObject());
        assertThat(testObject).isNotNull();
        assertThat(new String(testObject)).isEqualTo(JSON_TEST_OBJECT_STRING);
    }

    @Test
    void testreadValueStringClass() {
        assertThat(JsonUtils.readValue(JSON_TEST_OBJECT_STRING, UrlGroup.class)).isNotNull();
        assertThat(JsonUtils.readValue((String) null, UrlGroup.class)).isNull();
    }

    @Test
    void readValueByteClass() {
        assertThat(JsonUtils.readValue(JSON_TEST_OBJECT_STRING.getBytes(), UrlGroup.class)).isNotNull();
        assertThat(JsonUtils.readValue((byte[]) null, UrlGroup.class)).isNull();
    }

    @Test
    void readValueAsMap() {
        final String jsonInput = "{\"prop1\":\"abc\",\"prop2\":{\"prop2a\":\"def\",\"prop2b\":\"ghi\"},\"prop3\":[\"jkl\",\"mno\"]}";
        final Map<String, Object> map = JsonUtils.readValueAsMap(jsonInput);
        assertThat(map).containsEntry("prop1", "abc")
                .containsKey("prop3");
        assertThat(((Map<String, Object>) map.get("prop2")))
                .isInstanceOf(Map.class)
                .containsEntry("prop2a", "def")
                .containsEntry("prop2b", "ghi");
        assertThat((List<String>) map.get("prop3"))
                .isInstanceOf(List.class)
                .containsExactly("jkl", "mno");
    }

    @ParameterizedTest
    @ValueSource(strings = {"{", "}", "{\"prop1\":\"abc\","})
    void readValueAsMapInvalid(final String input) {
        assertThatExceptionOfType(JsonUtils.JsonUtilException.class)
                .isThrownBy(() -> JsonUtils.readValueAsMap(input));
    }

    @Test
    void readValueBytes() {
        assertThat(JsonUtils.readValue(JSON_TEST_OBJECT_STRING.getBytes(), new TypeReference<Map<String, Object>>() {
        })).isNotNull();
        assertThat(JsonUtils.readValue((byte[]) null, new TypeReference<Map<String, Object>>() {
        })).isNull();
    }

    @Test
    void readValueString() {
        assertThat(JsonUtils.readValue(JSON_TEST_OBJECT_STRING, new TypeReference<Map<String, Object>>() {
        })).isNotNull();
        assertThat(JsonUtils.readValue((String) null, new TypeReference<Map<String, Object>>() {
        })).isNull();
    }

    @Test
    void convertValue() {
        assertThat(JsonUtils.convertValue(null, UrlGroup.class)).isNull();
    }

    @Test
    void serializeExcludingProperties() {
        Map<String, String> groupProperties = JsonUtils.readValue(JSON_TEST_OBJECT_STRING, new TypeReference<>() {
        });
        String resultString = JsonUtils.serializeExcludingProperties(groupProperties, "group", "pattern", "any.limit", "category");
        assertThat(resultString).isEqualTo("{\"limit\":\"1000\"}");
    }

    @Test
    void serializeExcludingPropertiesInnerCallFails() {
        Map<String, String> groupProperties = JsonUtils.readValue(JSON_TEST_OBJECT_STRING, new TypeReference<>() {
        });
        assertThatExceptionOfType(JsonUtils.JsonUtilException.class).isThrownBy(() ->
                JsonUtils.serializeExcludingProperties(groupProperties, "limit.unknown"));
    }

    @Test
    void hasLength() {
        assertThat(JsonUtils.hasLength("X")).isTrue();
        assertThat(JsonUtils.hasLength("")).isFalse();
    }

    @Test
    void hasText() {
        assertThat(JsonUtils.hasText("X")).isTrue();
        assertThat(JsonUtils.hasText(" ")).isFalse();
    }

    @Test
    void cannotInstantiate() {
        Constructor<?>[] constructors = JsonUtils.class.getDeclaredConstructors();
        for (Constructor c : constructors) {
            c.setAccessible(true);
            try {
                c.newInstance();
                fail("JSonUtils should not be instantiable");
            } catch (InvocationTargetException e) {
                assertThat(e).isInstanceOf(InvocationTargetException.class);
                assertThat(e.getCause().getMessage()).isEqualTo("This is a utility class and cannot be instantiated");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Test

    void throwsException_writeValueAsString() throws JsonProcessingException {
        JsonUtils.JsonUtilException exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.writeValueAsString(new Object())
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.databind.exc.InvalidDefinitionException: No serializer found for class java.lang.Object");
    }

    @Test
    void throwsException_writeValueAsBytes() throws JsonProcessingException {
        JsonUtils.JsonUtilException exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.writeValueAsBytes(new Object())
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.databind.exc.InvalidDefinitionException: No serializer found for class java.lang.Object");
    }

    @Test
    void throwsException_readValue() throws JsonProcessingException {
        JsonUtils.JsonUtilException exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.readValue("invalid json", String.class)
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'invalid'");

        exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.readValue("invalid json".getBytes(), String.class)
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'invalid'");

        exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.readValue("invalid json", new TypeReference<String>() {})
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'invalid'");

        exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.readValue("invalid json".getBytes(), new TypeReference<String>() {})
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'invalid'");
    }

    @Test
    void throwsException_readValueAsMap() throws JsonProcessingException {
        JsonUtils.JsonUtilException exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.readValueAsMap("invalid json")
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'invalid'");
    }

    @Test
    void throwsException_convertValue() throws JsonProcessingException {
        JsonUtils.JsonUtilException exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.convertValue(Boolean.TRUE, Integer.class)
        );
        assertThat(exception.getMessage()).startsWith("java.lang.IllegalArgumentException: Cannot deserialize value of type `java.lang.Integer` from Boolean value");
    }

    @Test
    void throwsException_readTree() throws JsonProcessingException {
        assertThat(JsonUtils.readTree((String)null)).isNull();

        JsonUtils.JsonUtilException exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.readTree("invalid json")
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'invalid'");
    }

    @Test
    void throwsException_readTreeWithParserArg() throws JsonProcessingException {


        JsonUtils.JsonUtilException exception = assertThrows(JsonUtils.JsonUtilException.class,
                () -> JsonUtils.readValue("{'valid':'json'}", SerializerTestObject.class)
        );
        assertThat(exception.getMessage()).startsWith("com.fasterxml.jackson.core.JsonParseException: Unexpected character");
    }

    @Test
    void readNodes() throws JsonProcessingException {
        JsonUtils.readValue("""
                        {
                            "date": "1320105600000",
                            "glossary": {
                                "title": "example glossary",
                        		"GlossDiv": {
                                    "title": "S",
                        			"GlossList": {
                                        "GlossEntry": {
                                            "ID": "SGML",
                        					"SortAs": "SGML",
                        					"GlossTerm": "Standard Generalized Markup Language",
                        					"Acronym": "SGML",
                        					"Abbrev": "ISO 8879:1986",
                        					"GlossDef": {
                                                "para": "A meta-markup language, used to create markup languages such as DocBook.",
                        						"GlossSeeAlso": ["GML", "XML"]
                                            },
                        					"GlossSee": "markup"
                                        }
                                    }
                                }
                            }
                        }\
                        """, SerializerTestObject.class);
    }

    private Object getTestObject() {
        return new UrlGroup().setCategory("category").setGroup("group").setPattern("/pattern").setLimit(1_000L);
    }

    @JsonDeserialize(using = TestDeserializer.class)
    private static class SerializerTestObject {

    }
    private static class TestDeserializer extends JsonDeserializer<SerializerTestObject> {

        @Override
        public SerializerTestObject deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
            JsonNode node = JsonUtils.readTree(p);
            JsonUtils.getNodeAsBoolean(node, "invalid", true);
            JsonUtils.getNodeAsInt(node, "invalid", 0);
            JsonUtils.getNodeAsString(node, "valid", "");
            JsonUtils.getNodeAsDate(node, "invalid");
            JsonUtils.getNodeAsDate(node, "date");
            return null;
        }
    }
}
