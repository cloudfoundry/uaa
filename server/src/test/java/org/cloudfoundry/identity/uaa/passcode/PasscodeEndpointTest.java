package org.cloudfoundry.identity.uaa.passcode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.login.LoginInfoEndpoint;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PasscodeEndpointTest {
    private PasscodeEndpoint passcodeEndpoint;
    private UaaPrincipal marissa;
    ExpiringCodeStore mockExpiringCodeStore = mock(ExpiringCodeStore.class);

    @BeforeEach
    public void before() {
        passcodeEndpoint = new PasscodeEndpoint(mockExpiringCodeStore);
        when(mockExpiringCodeStore.generateCode(any(), any(), any(), any())).thenReturn(new ExpiringCode());
        marissa = new UaaPrincipal(
                "marissa-id", "marissa", "marissa@test.org", "origin", null, IdentityZoneHolder.get().getId()
        );
    }

    @Test
    void generatePasscodeForKnownUaaPrincipal() {
        Map<String, Object> model = new HashMap<>();
        assertEquals("passcode", passcodeEndpoint.generatePasscode(model, marissa));

        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<>(), new UaaAuthenticationDetails(new MockHttpServletRequest()));
        assertEquals("passcode", passcodeEndpoint.generatePasscode(model, uaaAuthentication));
    }

    @Test
    void generatePasscodeForKnownUaaPrincipalFromSamlToken() {
        Map<String, Object> model = new HashMap<>();

        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken = new ExpiringUsernameAuthenticationToken(marissa, "");
        //token with a UaaPrincipal should always work
        assertEquals("passcode", passcodeEndpoint.generatePasscode(model, expiringUsernameAuthenticationToken));

        //   This doesn't test the code path in generatePasscode for LoginSamlAuthenticationToken.
        //   Untested code path:
        //   https://github.com/cloudfoundry/uaa/blob/806ae16ba73a0e44d33b8e2561b766fe686b14a9/server/src/main/java/org/cloudfoundry/identity/uaa/login/LoginInfoEndpoint.java#L934
        UaaAuthentication samlAuthenticationToken = new LoginSamlAuthenticationToken(marissa, expiringUsernameAuthenticationToken).getUaaAuthentication(emptyList(), emptySet(), new LinkedMultiValueMap<>());
        assertEquals("passcode", passcodeEndpoint.generatePasscode(model, samlAuthenticationToken));
    }

    @Test
    void generatePasscodeForUnknownUaaPrincipal() {
        Map<String, Object> model = new HashMap<>();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("principal", "");
        assertThrows(LoginInfoEndpoint.UnknownPrincipalException.class, () -> passcodeEndpoint.generatePasscode(model, token));
    }
}