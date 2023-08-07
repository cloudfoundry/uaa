package org.cloudfoundry.identity.uaa.oauth.token;

import com.nimbusds.jose.util.Base64URL;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntrospectionClaimsTest {

  private final static String TOKEN_PAYLOAD = "eyJqdGkiOiJiODc5MzNkYmQ3MDM0ZTZjODE1MDZmOTljODUwYWUwYSIsImNsaWVudF9hdXRoX21ldGhvZCI6Im5vbmUiLCJzdWIiOiJiZjNkOTJhNC1jNGVjLTQxMDQtOGJmNS0yZTMwMTFmZDQxODUiLCJzY29wZSI6WyJvcGVuaWQiXSwiY2xpZW50X2lkIjoibG9naW4iLCJjaWQiOiJsb2dpbiIsImF6cCI6ImxvZ2luIiwicmV2b2NhYmxlIjp0cnVlLCJncmFudF90eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwidXNlcl9pZCI6ImJmM2Q5MmE0LWM0ZWMtNDEwNC04YmY1LTJlMzAxMWZkNDE4NSIsIm9yaWdpbiI6Imlhcy5wcm94eSIsInVzZXJfbmFtZSI6IkZpcnN0Lk5hbWVAZW1haWwub3JnIiwiZW1haWwiOiJGaXJzdC5OYW1lQGVtYWlsLm9yZyIsImF1dGhfdGltZSI6MTY4OTE3ODg2MiwicmV2X3NpZyI6IjIzYmRhYmZkIiwiaWF0IjoxNjg5MTc4ODYzLCJleHAiOjE2ODkyMjIwNjMsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iLCJ6aWQiOiJ1YWEiLCJhdWQiOlsib3BlbmlkIiwibG9naW4iXX0";
  private IntrospectionClaims INTROSPECTION_PAYLOAD;

  @BeforeEach
  void setup() throws ParseException {
    String json = new Base64URL(TOKEN_PAYLOAD).decodeToString();
    INTROSPECTION_PAYLOAD = JsonUtils.readValue(json, IntrospectionClaims.class);
    INTROSPECTION_PAYLOAD.setActive(false);
  }

  @Test
  void setActive() {
    INTROSPECTION_PAYLOAD.setActive(true);
    assertTrue(INTROSPECTION_PAYLOAD.isActive());
  }

  @Test
  void isActive() {
    assertFalse(INTROSPECTION_PAYLOAD.isActive());
  }

  @Test
  void testSerialize() {
    assertTrue(JsonUtils.writeValueAsString(INTROSPECTION_PAYLOAD).contains(TokenConstants.CLIENT_AUTH_NONE));
  }
}
