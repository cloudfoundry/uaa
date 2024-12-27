package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientDetailsCreationTest {

    ClientDetailsCreation clientDetailsCreation = new ClientDetailsCreation();

    @Test
    void testRequestSerialization() {
        clientDetailsCreation.setJsonWebKeyUri("https://uri.domain.net");
        clientDetailsCreation.setJsonWebKeySet("{}");
        String jsonRequest = JsonUtils.writeValueAsString(clientDetailsCreation);
        ClientDetailsCreation request = JsonUtils.readValue(jsonRequest, ClientDetailsCreation.class);
        assertEquals(clientDetailsCreation, request);
    }
}