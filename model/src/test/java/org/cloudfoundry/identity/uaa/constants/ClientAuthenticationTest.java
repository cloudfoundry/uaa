package org.cloudfoundry.identity.uaa.constants;

import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.CLIENT_SECRET_BASIC;
import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.CLIENT_SECRET_POST;
import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.NONE;
import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.PRIVATE_KEY_JWT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientAuthenticationTest {

    @Test
    void secretNeeded() {
        assertTrue(ClientAuthentication.secretNeeded(CLIENT_SECRET_POST));
        assertTrue(ClientAuthentication.secretNeeded(CLIENT_SECRET_BASIC));
        assertFalse(ClientAuthentication.secretNeeded(NONE));
        assertFalse(ClientAuthentication.secretNeeded(PRIVATE_KEY_JWT));
    }

    @Test
    void isMethodSupported() {
        assertTrue(ClientAuthentication.isMethodSupported(CLIENT_SECRET_POST));
        assertFalse(ClientAuthentication.isMethodSupported("foo"));
    }

    @Test
    void isValidMethodTrue() {
        assertTrue(ClientAuthentication.isValidMethod(NONE, false, false));
        assertTrue(ClientAuthentication.isValidMethod(PRIVATE_KEY_JWT, false, true));
        assertTrue(ClientAuthentication.isValidMethod(CLIENT_SECRET_POST, true, false));
        assertTrue(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, true, false));
        // legacy checks, no method passed
        assertTrue(ClientAuthentication.isValidMethod(null, false, false));
        assertTrue(ClientAuthentication.isValidMethod(null, true, false));
        assertTrue(ClientAuthentication.isValidMethod(null, false, true));

    }

    @Test
    void isValidMethodFalse() {
        assertFalse(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, false, false));
        assertFalse(ClientAuthentication.isValidMethod(CLIENT_SECRET_POST, false, false));
        assertFalse(ClientAuthentication.isValidMethod(NONE, true, false));
        assertFalse(ClientAuthentication.isValidMethod(PRIVATE_KEY_JWT, true, true));
        assertFalse(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, true, true));
        // legacy checks, no method passed
        assertFalse(ClientAuthentication.isValidMethod(null, true, true));
    }

    @Test
    void getCalculatedMethod() {
        assertEquals(NONE, ClientAuthentication.getCalculatedMethod(NONE, false, false));
        assertEquals(NONE, ClientAuthentication.getCalculatedMethod(null, false, false));
        assertEquals(PRIVATE_KEY_JWT, ClientAuthentication.getCalculatedMethod(PRIVATE_KEY_JWT, false, true));
        assertEquals(PRIVATE_KEY_JWT, ClientAuthentication.getCalculatedMethod(null, false, true));
        assertEquals(CLIENT_SECRET_BASIC, ClientAuthentication.getCalculatedMethod(CLIENT_SECRET_BASIC, true, false));
        assertEquals(CLIENT_SECRET_BASIC, ClientAuthentication.getCalculatedMethod(null, true, false));
    }

    @Test
    void isAuthMethodEqualTrue() {
        assertTrue(ClientAuthentication.isAuthMethodEqual(NONE, NONE));
        assertTrue(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_BASIC, CLIENT_SECRET_POST));
        assertTrue(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_POST, CLIENT_SECRET_BASIC));
        assertTrue(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_BASIC, CLIENT_SECRET_BASIC));
        assertTrue(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_POST, CLIENT_SECRET_POST));
        assertTrue(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, PRIVATE_KEY_JWT));
        assertTrue(ClientAuthentication.isAuthMethodEqual(null, null));
        assertTrue(ClientAuthentication.isAuthMethodEqual(null, CLIENT_SECRET_BASIC));
        assertTrue(ClientAuthentication.isAuthMethodEqual(null, CLIENT_SECRET_POST));
        assertTrue(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_BASIC, null));
    }

    @Test
    void isAuthMethodEqualFalse() {
        assertFalse(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, null));
        assertFalse(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, CLIENT_SECRET_BASIC));
        assertFalse(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, NONE));
    }
}
