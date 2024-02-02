package org.cloudfoundry.identity.uaa.passcode;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class PasscodeInformationTest {
    private UaaPrincipal uaaPrincipal;
    Map<String, Object> authorizationParameters = null;

    @BeforeEach
    public void before() {
        uaaPrincipal = new UaaPrincipal(
                "marissa-id", "marissa", "marissa@test.org", "origin", null, IdentityZoneHolder.get().getId()
        );
    }

    @Test
    void buildPasscodeInformationForKnownUaaPrincipal() {
        final PasscodeInformation passcodeInformation =
                new PasscodeInformation(uaaPrincipal, authorizationParameters);

        assertNull(passcodeInformation.getPasscode());
        assertEquals(uaaPrincipal.getName(), passcodeInformation.getUsername());
        assertEquals(uaaPrincipal.getOrigin(), passcodeInformation.getOrigin());
        assertEquals(uaaPrincipal.getId(), passcodeInformation.getUserId());
    }

    @Test
    void buildPasscodeInformationFromUaaAuthentication() {
        UaaAuthentication uaaAuthentication = new UaaAuthentication(
                uaaPrincipal,
                new ArrayList<>(),
                new UaaAuthenticationDetails(new MockHttpServletRequest())
        );

        final PasscodeInformation passcodeInformation =
                new PasscodeInformation(uaaAuthentication, authorizationParameters);

        assertNull(passcodeInformation.getPasscode());
        assertEquals(uaaPrincipal.getName(), passcodeInformation.getUsername());
        assertEquals(uaaPrincipal.getOrigin(), passcodeInformation.getOrigin());
        assertEquals(uaaPrincipal.getId(), passcodeInformation.getUserId());
    }

    @Test
    void buildPasscodeFromExpiringToken() {
        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken =
                new ExpiringUsernameAuthenticationToken(uaaPrincipal, "");

        final PasscodeInformation passcodeInformation =
                new PasscodeInformation(expiringUsernameAuthenticationToken, authorizationParameters);

        assertNull(passcodeInformation.getPasscode());
        assertEquals(uaaPrincipal.getName(), passcodeInformation.getUsername());
        assertEquals(uaaPrincipal.getOrigin(), passcodeInformation.getOrigin());
        assertEquals(uaaPrincipal.getId(), passcodeInformation.getUserId());
    }

    @Test
    void buildPasscodeInformationFromSamlToken() {
        Principal principal = mock(Principal.class);
        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken =
                new ExpiringUsernameAuthenticationToken(principal, "");
        LoginSamlAuthenticationToken samlAuthenticationToken = new LoginSamlAuthenticationToken(
                uaaPrincipal,
                expiringUsernameAuthenticationToken
        );

        final PasscodeInformation passcodeInformation =
                new PasscodeInformation(samlAuthenticationToken, authorizationParameters);

        assertNull(passcodeInformation.getPasscode());
        assertEquals(uaaPrincipal.getName(), passcodeInformation.getUsername());
        assertEquals(uaaPrincipal.getOrigin(), passcodeInformation.getOrigin());
        assertEquals(uaaPrincipal.getId(), passcodeInformation.getUserId());
    }

    @Test
    void passcodeInformationThrowsExceptionOnUnknownPrincipal() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("unknown principal type", "");
        assertThrows(PasscodeEndpoint.UnknownPrincipalException.class, () ->
                new PasscodeInformation(token, authorizationParameters));
    }
}