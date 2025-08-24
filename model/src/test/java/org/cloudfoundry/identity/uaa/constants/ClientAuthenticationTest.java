package org.cloudfoundry.identity.uaa.constants;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.CLIENT_SECRET_BASIC;
import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.CLIENT_SECRET_POST;
import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.NONE;
import static org.cloudfoundry.identity.uaa.constants.ClientAuthentication.PRIVATE_KEY_JWT;

class ClientAuthenticationTest {

    @Test
    void secretNeeded() {
        assertThat(ClientAuthentication.secretNeeded(CLIENT_SECRET_POST)).isTrue();
        assertThat(ClientAuthentication.secretNeeded(CLIENT_SECRET_BASIC)).isTrue();
        assertThat(ClientAuthentication.secretNeeded(NONE)).isFalse();
        assertThat(ClientAuthentication.secretNeeded(PRIVATE_KEY_JWT)).isFalse();
    }

    @Test
    void isMethodSupported() {
        assertThat(ClientAuthentication.isMethodSupported(CLIENT_SECRET_POST)).isTrue();
        assertThat(ClientAuthentication.isMethodSupported("foo")).isFalse();
    }

    @Test
    void isValidMethodTrue() {
        assertThat(ClientAuthentication.isValidMethod(NONE, false, false)).isTrue();
        assertThat(ClientAuthentication.isValidMethod(PRIVATE_KEY_JWT, false, true)).isTrue();
        assertThat(ClientAuthentication.isValidMethod(CLIENT_SECRET_POST, true, false)).isTrue();
        assertThat(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, true, false)).isTrue();
        // legacy checks, no method passed
        assertThat(ClientAuthentication.isValidMethod(null, false, false)).isTrue();
        assertThat(ClientAuthentication.isValidMethod(null, true, false)).isTrue();
        assertThat(ClientAuthentication.isValidMethod(null, false, true)).isTrue();

    }

    @Test
    void isValidMethodFalse() {
        assertThat(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, false, false)).isFalse();
        assertThat(ClientAuthentication.isValidMethod(CLIENT_SECRET_POST, false, false)).isFalse();
        assertThat(ClientAuthentication.isValidMethod(NONE, true, false)).isFalse();
        assertThat(ClientAuthentication.isValidMethod(PRIVATE_KEY_JWT, true, true)).isFalse();
        assertThat(ClientAuthentication.isValidMethod(CLIENT_SECRET_BASIC, true, true)).isFalse();
        // legacy checks, no method passed
        assertThat(ClientAuthentication.isValidMethod(null, true, true)).isFalse();
    }

    @Test
    void getCalculatedMethod() {
        assertThat(ClientAuthentication.getCalculatedMethod(NONE, false, false)).isEqualTo(NONE);
        assertThat(ClientAuthentication.getCalculatedMethod(null, false, false)).isEqualTo(NONE);
        assertThat(ClientAuthentication.getCalculatedMethod(PRIVATE_KEY_JWT, false, true)).isEqualTo(PRIVATE_KEY_JWT);
        assertThat(ClientAuthentication.getCalculatedMethod(null, false, true)).isEqualTo(PRIVATE_KEY_JWT);
        assertThat(ClientAuthentication.getCalculatedMethod(CLIENT_SECRET_BASIC, true, false)).isEqualTo(CLIENT_SECRET_BASIC);
        assertThat(ClientAuthentication.getCalculatedMethod(null, true, false)).isEqualTo(CLIENT_SECRET_BASIC);
    }

    @Test
    void isAuthMethodEqualTrue() {
        assertThat(ClientAuthentication.isAuthMethodEqual(NONE, NONE)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_BASIC, CLIENT_SECRET_POST)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_POST, CLIENT_SECRET_BASIC)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_BASIC, CLIENT_SECRET_BASIC)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_POST, CLIENT_SECRET_POST)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, PRIVATE_KEY_JWT)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(null, null)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(null, CLIENT_SECRET_BASIC)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(null, CLIENT_SECRET_POST)).isTrue();
        assertThat(ClientAuthentication.isAuthMethodEqual(CLIENT_SECRET_BASIC, null)).isTrue();
    }

    @Test
    void isAuthMethodEqualFalse() {
        assertThat(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, null)).isFalse();
        assertThat(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, CLIENT_SECRET_BASIC)).isFalse();
        assertThat(ClientAuthentication.isAuthMethodEqual(PRIVATE_KEY_JWT, NONE)).isFalse();
    }
}
