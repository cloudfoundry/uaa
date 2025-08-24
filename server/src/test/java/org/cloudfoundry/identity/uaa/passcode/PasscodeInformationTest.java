package org.cloudfoundry.identity.uaa.passcode;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PasscodeInformationTest {
    private UaaPrincipal uaaPrincipal;
    Map<String, Object> authorizationParameters;

    @BeforeEach
    void before() {
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

        assertThat(passcodeInformation.getPasscode()).isNull();
        assertThat(passcodeInformation.getUsername()).isEqualTo(uaaPrincipal.getName());
        assertThat(passcodeInformation.getOrigin()).isEqualTo(uaaPrincipal.getOrigin());
        assertThat(passcodeInformation.getUserId()).isEqualTo(uaaPrincipal.getId());
        assertThat(passcodeInformation.getSamlAuthorities()).isEqualTo(Collections.emptyList());
    }

    @Test
    void buildPasscodeInformationForKnownUaaPrincipal() {
        final PasscodeInformation passcodeInformation =
                new PasscodeInformation(uaaPrincipal, authorizationParameters);

        assertThat(passcodeInformation.getPasscode()).isNull();
        assertThat(passcodeInformation.getUsername()).isEqualTo(uaaPrincipal.getName());
        assertThat(passcodeInformation.getOrigin()).isEqualTo(uaaPrincipal.getOrigin());
        assertThat(passcodeInformation.getUserId()).isEqualTo(uaaPrincipal.getId());
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

        assertThat(passcodeInformation.getPasscode()).isNull();
        assertThat(passcodeInformation.getUsername()).isEqualTo(uaaPrincipal.getName());
        assertThat(passcodeInformation.getOrigin()).isEqualTo(uaaPrincipal.getOrigin());
        assertThat(passcodeInformation.getUserId()).isEqualTo(uaaPrincipal.getId());
    }

    @Test
    void passcodeInformationThrowsExceptionOnUnknownPrincipal() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("unknown principal type", "");
        assertThatExceptionOfType(PasscodeEndpoint.UnknownPrincipalException.class).isThrownBy(() ->
                new PasscodeInformation(token, authorizationParameters));
    }

    @Test
    void passcodeInformationThrowExceptionOnNonUaaPrincipal() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(mock(Principal.class));

        assertThatExceptionOfType(PasscodeEndpoint.UnknownPrincipalException.class).isThrownBy(() ->
                new PasscodeInformation(authentication, authorizationParameters));
    }
}