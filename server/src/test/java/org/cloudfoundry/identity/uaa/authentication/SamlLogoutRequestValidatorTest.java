package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SamlLogoutRequestValidatorTest {

    @Mock
    private Saml2LogoutRequestValidator delegate;
    private SamlLogoutRequestValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SamlLogoutRequestValidator(delegate);
    }

    @Test
    void validatePassesThruSuccess() {
        Saml2LogoutValidatorResult success = Saml2LogoutValidatorResult.success();
        when(delegate.validate(any())).thenReturn(success);
        Saml2LogoutValidatorResult result = validator.validate(null);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void validateRemovesMissingSignatureError() {
        Saml2Error signatureError = new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE, "Missing signature for object");
        when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.withErrors(signatureError).build());
        Saml2LogoutValidatorResult result = validator.validate(null);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void validateDifferentErrorIsPassedThru() {
        Saml2Error signatureError = new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE, "Failed to match issuer to configured issuer");
        when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.withErrors(signatureError).build());
        Saml2LogoutValidatorResult result = validator.validate(null);
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void unsignedRequestSucceedsWithoutCallingDelegate() {
        Saml2LogoutRequest logoutRequest = mock(Saml2LogoutRequest.class);
        when(logoutRequest.getParameters()).thenReturn(Collections.emptyMap());
        Saml2LogoutRequestValidatorParameters parameters = mock(Saml2LogoutRequestValidatorParameters.class);
        when(parameters.getLogoutRequest()).thenReturn(logoutRequest);

        Saml2LogoutValidatorResult result = validator.validate(parameters);

        assertThat(result.hasErrors()).isFalse();
        verify(delegate, never()).validate(any());
    }
}