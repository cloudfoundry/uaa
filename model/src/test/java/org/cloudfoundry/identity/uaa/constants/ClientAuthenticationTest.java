package org.cloudfoundry.identity.uaa.constants;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ClientAuthenticationTest {

  @Test
  void secretNeeded() {
    assertTrue(ClientAuthentication.secretNeeded(ClientAuthentication.CLIENT_SECRET_POST));
    assertTrue(ClientAuthentication.secretNeeded(ClientAuthentication.CLIENT_SECRET_BASIC));
    assertFalse(ClientAuthentication.secretNeeded(ClientAuthentication.NONE));
    assertFalse(ClientAuthentication.secretNeeded(ClientAuthentication.PRIVATE_KEY_JWT));
  }

  @Test
  void isMethodSupported() {
    assertTrue(ClientAuthentication.isMethodSupported(ClientAuthentication.CLIENT_SECRET_POST));
    assertFalse(ClientAuthentication.isMethodSupported("foo"));
  }

  @Test
  void isValidMethod() {
    assertTrue(ClientAuthentication.isValidMethod(ClientAuthentication.NONE, null));
    assertTrue(ClientAuthentication.isValidMethod(ClientAuthentication.PRIVATE_KEY_JWT, null));
    assertTrue(ClientAuthentication.isValidMethod(ClientAuthentication.CLIENT_SECRET_POST, "secret"));
    assertTrue(ClientAuthentication.isValidMethod(ClientAuthentication.CLIENT_SECRET_BASIC, "secret"));
    assertTrue(ClientAuthentication.isValidMethod(null, null));
    assertTrue(ClientAuthentication.isValidMethod(null, "secret"));
    assertFalse(ClientAuthentication.isValidMethod(ClientAuthentication.CLIENT_SECRET_BASIC, null));
    assertFalse(ClientAuthentication.isValidMethod(ClientAuthentication.CLIENT_SECRET_POST, null));
    assertFalse(ClientAuthentication.isValidMethod(ClientAuthentication.NONE, "secret"));
    assertFalse(ClientAuthentication.isValidMethod(ClientAuthentication.PRIVATE_KEY_JWT, "secret"));
  }
}