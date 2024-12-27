package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

class ClientJwtChangeRequestTest {

    @Test
    void testRequestSerialization() {
        ClientJwtChangeRequest def = new ClientJwtChangeRequest(null, null, null);
        def.setKeyId("key-1");
        def.setChangeMode(ClientJwtChangeRequest.ChangeMode.DELETE);
        def.setJsonWebKeyUri("http://localhost:8080/uaa/token_key");
        def.setJsonWebKeySet("{}");
        def.setClientId("admin");
        String jsonRequest = JsonUtils.writeValueAsString(def);
        ClientJwtChangeRequest request = JsonUtils.readValue(jsonRequest, ClientJwtChangeRequest.class);
        assertNotEquals(def, request);
    }

}
