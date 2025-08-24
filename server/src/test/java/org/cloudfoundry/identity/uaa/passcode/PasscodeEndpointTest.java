package org.cloudfoundry.identity.uaa.passcode;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PasscodeEndpointTest {
    private PasscodeEndpoint passcodeEndpoint;
    private UaaPrincipal marissa;
    ExpiringCodeStore mockExpiringCodeStore = mock(ExpiringCodeStore.class);
    final String testPasscode = "test passcode";

    @BeforeEach
    void before() {
        passcodeEndpoint = new PasscodeEndpoint(mockExpiringCodeStore);
        ExpiringCode expiringCode = new ExpiringCode(testPasscode, null, "data", "intent");
        when(mockExpiringCodeStore.generateCode(any(), any(), any(), any())).thenReturn(expiringCode);
        marissa = new UaaPrincipal(
                "marissa-id", "marissa", "marissa@test.org", "origin", null, IdentityZoneHolder.get().getId()
        );
    }

    @Test
    void generatePasscodeForKnownUaaPrincipal() {
        Map<String, Object> model = new HashMap<>();

        assertThat(passcodeEndpoint.generatePasscode(model, marissa)).isEqualTo("passcode");

        String actualPasscode = (String) model.get("passcode");
        assertThat(actualPasscode).isEqualTo(testPasscode);
    }
}