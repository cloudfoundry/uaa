package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

class PrivateKeyChangeRequestTest {

  @Test
  void testRequestSerialization() {
    PrivateKeyChangeRequest def = new PrivateKeyChangeRequest(null, null, null);
    def.setKeyId("key-1");
    def.setChangeMode(PrivateKeyChangeRequest.ChangeMode.DELETE);
    def.setKeyUrl("http://localhost:8080/uaa/token_key");
    def.setKeyConfig("{}");
    def.setClientId("admin");
    String jsonRequest = JsonUtils.writeValueAsString(def);
    PrivateKeyChangeRequest request = JsonUtils.readValue(jsonRequest, PrivateKeyChangeRequest.class);
    assertNotEquals(def, request);
  }

}
