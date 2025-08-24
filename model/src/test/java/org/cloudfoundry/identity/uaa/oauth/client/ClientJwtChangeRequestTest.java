package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ClientJwtChangeRequestTest {

    @Test
    void requestSerialization() {
        ClientJwtChangeRequest def = new ClientJwtChangeRequest(null, null, null);
        def.setKeyId("key-1");
        def.setChangeMode(ClientJwtChangeRequest.ChangeMode.DELETE);
        def.setJsonWebKeyUri("http://localhost:8080/uaa/token_key");
        def.setJsonWebKeySet("{}");
        def.setClientId("admin");
        String jsonRequest = JsonUtils.writeValueAsString(def);
        ClientJwtChangeRequest request = JsonUtils.readValue(jsonRequest, ClientJwtChangeRequest.class);
        assertThat(request).isNotEqualTo(def);
    }

    @Test
    void requestSerializationFederated() {
        ClientJwtChangeRequest def = new ClientJwtChangeRequest();
        def.setKeyId("key-1");
        def.setChangeMode(ClientJwtChangeRequest.ChangeMode.DELETE);
        def.setIssuer("http://localhost:8080/uaa/oauth/token");
        def.setSubject("admin-client");
        def.setAudience("http://localhost:8080/uaa/oauth/token");
        assertThat(def.isFederated()).isTrue();
        String jsonRequest = JsonUtils.writeValueAsString(def);
        ClientJwtChangeRequest request = JsonUtils.readValue(jsonRequest, ClientJwtChangeRequest.class);
        assertThat(request).isNotEqualTo(def);
        assertThat(def.getFederation()).isNotNull();
    }
}
