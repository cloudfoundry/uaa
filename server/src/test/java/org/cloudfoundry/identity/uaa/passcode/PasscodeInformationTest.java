package org.cloudfoundry.identity.uaa.passcode;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
//import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Ignore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
    void buildPasscodeInformationForUserAttributes() {
        final PasscodeInformation passcodeInformation =
            new PasscodeInformation(uaaPrincipal.getId(),
                uaaPrincipal.getName(),
                null,
                uaaPrincipal.getOrigin(),
                Collections.emptyList());

        assertNull(passcodeInformation.getPasscode());
        assertEquals(uaaPrincipal.getName(), passcodeInformation.getUsername());
        assertEquals(uaaPrincipal.getOrigin(), passcodeInformation.getOrigin());
        assertEquals(uaaPrincipal.getId(), passcodeInformation.getUserId());
        assertEquals(Collections.emptyList(), passcodeInformation.getSamlAuthorities());
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
    @Ignore("SAML test doesn't compile")
    void buildPasscodeFromExpiringToken() {
//        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken =
//                new ExpiringUsernameAuthenticationToken(uaaPrincipal, "");
//
//        final PasscodeInformation passcodeInformation =
//                new PasscodeInformation(expiringUsernameAuthenticationToken, authorizationParameters);
//
//        assertNull(passcodeInformation.getPasscode());
//        assertEquals(uaaPrincipal.getName(), passcodeInformation.getUsername());
//        assertEquals(uaaPrincipal.getOrigin(), passcodeInformation.getOrigin());
//        assertEquals(uaaPrincipal.getId(), passcodeInformation.getUserId());
    }

    @Test
    @Ignore("SAML test doesn't compile")
    void buildPasscodeInformationFromSamlToken() {
        Principal principal = mock(Principal.class);
//        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken =
//                new ExpiringUsernameAuthenticationToken(principal, "");
//        LoginSamlAuthenticationToken samlAuthenticationToken = new LoginSamlAuthenticationToken(
//                uaaPrincipal,
//                expiringUsernameAuthenticationToken
//        );
//
//        final PasscodeInformation passcodeInformation =
//                new PasscodeInformation(samlAuthenticationToken, authorizationParameters);
//
//        assertNull(passcodeInformation.getPasscode());
//        assertEquals(uaaPrincipal.getName(), passcodeInformation.getUsername());
//        assertEquals(uaaPrincipal.getOrigin(), passcodeInformation.getOrigin());
//        assertEquals(uaaPrincipal.getId(), passcodeInformation.getUserId());
    }

    @Test
    void passcodeInformationThrowsExceptionOnUnknownPrincipal() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("unknown principal type", "");
        assertThrows(PasscodeEndpoint.UnknownPrincipalException.class, () ->
                new PasscodeInformation(token, authorizationParameters));
    }

    @Test
    void passcodeInformationThrowExceptionOnNonUaaPrincipal() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(mock(Principal.class));

        assertThrows(PasscodeEndpoint.UnknownPrincipalException.class, () ->
                new PasscodeInformation(authentication, authorizationParameters));
    }
}