package org.cloudfoundry.identity.uaa.oauth.client;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


class ClientJwtCredentialTest {

    @Test
    void parse() {
        assertDoesNotThrow(() -> ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]"));
        List<ClientJwtCredential> federationList = ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"},{\"iss\":\"http://localhost:8080/uaa\"}]");
        assertEquals(2, federationList.size());
    }

    @Test
    void testConstructor() {
        ClientJwtCredential jwtCredential = new ClientJwtCredential("subject", "issuer", "audience");
        assertTrue(jwtCredential.getSubject().equals("subject"));
        assertTrue(jwtCredential.getIssuer().equals("issuer"));
        assertTrue(jwtCredential.getAudience().equals("audience"));
        assertTrue(jwtCredential.isValid());
        jwtCredential = new ClientJwtCredential();
        assertFalse(jwtCredential.isValid());
    }

    @Test
    void testDeserializer() {
        assertFalse(ClientJwtCredential.parse("[{\"iss\":\"issuer\"}]").iterator().next().isValid());
    }

    @Test
    void testDeserializerException() {
        assertThrows(IllegalArgumentException.class, () -> ClientJwtCredential.parse("[\"iss\":\"issuer\"]"));
    }
}
