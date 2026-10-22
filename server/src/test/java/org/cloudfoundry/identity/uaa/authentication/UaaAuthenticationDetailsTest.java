package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import jakarta.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class UaaAuthenticationDetailsTest {

    @Test
    void toStringDoesNotContainSessionId() {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(false, "clientid", "origin", "1234");
        String toString = details.toString();
        assertThat(toString).contains("sessionId=<SESSION>");
    }

    @Test
    void buildValidAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("clientId", "a");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertThat(details.getClientId()).isEqualTo("a");
    }

    @Test
    void buildWithoutAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertThat(details.getClientId()).isNull();
    }

    @Test
    void noLoginHint() {
        HttpServletRequest request = new MockHttpServletRequest();

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "cliendId");
        assertThat(details.getLoginHint()).isNull();
    }

    @Test
    void publicTokenRequest() {
        HttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "cliendId");
        details.setAuthenticationMethod("none");
        assertThat(details.getLoginHint()).isNull();
        assertThat(details.isAuthorizationSet()).isFalse();
        assertThat(details.getRequestPath()).isEqualTo("/oauth/token");
        assertThat(details.getAuthenticationMethod()).isEqualTo("none");
    }

    @Test
    void savesRequestParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("key", "value");

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertThat(details.getParameterMap().get("key")[0]).isEqualTo("value");
    }

    @Test
    void doesNotSaveUsernamePasswordRequestParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String[] filteredKeys = {"Username", "username", "Password", "password", "Passcode", "passcode"};
        for (String key : filteredKeys) {
            request.addParameter(key, "value");
        }

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        for (String key : filteredKeys) {
            assertThat(details.getParameterMap()).doesNotContainKey(key);
        }
    }

    /**
     * UaaAuthenticationDetails is stored in Spring Session through the security context, so a node
     * running this version must read sessions written by the previous release and vice versa.
     */
    @Test
    void serialVersionUidMatchesThePreviousRelease() {
        assertThat(java.io.ObjectStreamClass.lookup(UaaAuthenticationDetails.class).getSerialVersionUID())
                .isEqualTo(4782409396359737075L);
    }

    @Test
    void deserializesAnInstanceWrittenByThePreviousRelease() throws Exception {
        byte[] bytes;
        try (var in = getClass().getResourceAsStream("UaaAuthenticationDetails-develop.ser.b64")) {
            assertThat(in).isNotNull();
            bytes = java.util.Base64.getDecoder().decode(new String(in.readAllBytes()).trim());
        }
        UaaAuthenticationDetails details;
        try (var in = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bytes))) {
            details = (UaaAuthenticationDetails) in.readObject();
        }

        assertThat(details.getClientId()).isEqualTo("app");
        assertThat(details.getOrigin()).isEqualTo("10.0.0.1");
        assertThat(details.getServletPath()).as("absent from the previous release's form").isNull();
        assertThat(ClientDetailsAuthenticationProvider.isTlsClientAuthPath(details)).isFalse();
    }

    @Test
    void servletPathSurvivesSerialization() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/uaa/oauth/mtls/token");
        request.setServletPath("/oauth/mtls/token");
        var bytes = new java.io.ByteArrayOutputStream();
        try (var out = new java.io.ObjectOutputStream(bytes)) {
            out.writeObject(new UaaAuthenticationDetails(request, "app"));
        }
        try (var in = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bytes.toByteArray()))) {
            assertThat(((UaaAuthenticationDetails) in.readObject()).getServletPath()).isEqualTo("/oauth/mtls/token");
        }
    }
}
