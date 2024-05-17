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
  void isValidMethod() {
    assertTrue(ClientAuthentication.isValidMethod(NONE, false, false));
    assertTrue(ClientAuthentication.isValidMethod(PRIVATE_KEY_JWT, false, true));
    assertTrue(ClientAuthentication.isValidMethod(CLIENT_SECRET_POST, true, false));
    assertTrue(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, true, false));
    assertTrue(ClientAuthentication.isValidMethod(null, false, false));
    assertTrue(ClientAuthentication.isValidMethod(null, true, false));
    assertFalse(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, false, false));
    assertFalse(ClientAuthentication.isValidMethod(CLIENT_SECRET_POST, false, false));
    assertFalse(ClientAuthentication.isValidMethod(NONE, true, false));
    assertFalse(ClientAuthentication.isValidMethod(PRIVATE_KEY_JWT, true, true));
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
}