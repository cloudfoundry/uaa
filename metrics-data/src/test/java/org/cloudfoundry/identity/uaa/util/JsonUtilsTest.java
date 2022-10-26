package org.cloudfoundry.identity.uaa.util;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.metrics.UrlGroup;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JsonUtilsTest {
  private static final String jsonTestObjectString = "{\"pattern\":\"/pattern\",\"group\":\"group\",\"limit\":1000,\"category\":\"category\"}";

  @Test
  void writeValueAsString() {
    String testObjectString = JsonUtils.writeValueAsString(getTestObject());
    assertNotNull(testObjectString);
    assertEquals(jsonTestObjectString, testObjectString);
  }

  @Test
  void writeValueAsBytes() {
    byte[] testObject = JsonUtils.writeValueAsBytes(getTestObject());
    assertNotNull(testObject);
    assertEquals(jsonTestObjectString, new String(testObject));
  }

  @Test
  void testreadValueStringClass() {
    assertNotNull(JsonUtils.readValue(jsonTestObjectString, UrlGroup.class));
    assertNull(JsonUtils.readValue((String)null, UrlGroup.class));
  }

  @Test
  void testReadValueByteClass() {
    assertNotNull(JsonUtils.readValue(jsonTestObjectString.getBytes(), UrlGroup.class));
    assertNull(JsonUtils.readValue((byte[]) null, UrlGroup.class));
  }

  @Test
  void testReadValueBytes() {
    assertNotNull(JsonUtils.readValue(jsonTestObjectString.getBytes(), new TypeReference<Map<String, Object>>() {}));
    assertNull(JsonUtils.readValue((byte[])null, new TypeReference<Map<String, Object>>() {}));
  }

  @Test
  void testReadValueString() {
    assertNotNull(JsonUtils.readValue(jsonTestObjectString, new TypeReference<Map<String, Object>>() {}));
    assertNull(JsonUtils.readValue((String)null, new TypeReference<Map<String, Object>>() {}));
  }

  @Test
  void testConvertValue() {
    assertNull(JsonUtils.convertValue(null, UrlGroup.class));
  }


  @Test
  void testSerializeExcludingProperties() {
    Map<String, String> groupProperties = JsonUtils.readValue(jsonTestObjectString, new TypeReference<Map<String, String>>() {});
    String resultString = JsonUtils.serializeExcludingProperties(groupProperties, "group", "pattern", "any.limit", "category");
    assertEquals("{\"limit\":\"1000\"}", resultString);
  }

  @Test
  void testSerializeExcludingPropertiesInnerCallFailed() {
    Map<String, String> groupProperties = JsonUtils.readValue(jsonTestObjectString, new TypeReference<Map<String, String>>() {});
    try {
      JsonUtils.serializeExcludingProperties(groupProperties, "limit.unkonwn");
      fail("not expected");
    } catch (Exception e) {
      assertTrue(e instanceof JsonUtils.JsonUtilException);
    }
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