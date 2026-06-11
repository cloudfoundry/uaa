package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SamlLogoutResponseValidatorTest {

    @Mock
    private Saml2LogoutResponseValidator delegate;
    private SamlLogoutResponseValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SamlLogoutResponseValidator(delegate);
    }

    @Test
    void validatePassesThruSuccess() {
        Saml2LogoutValidatorResult success = Saml2LogoutValidatorResult.success();
        when(delegate.validate(any())).thenReturn(success);
        Saml2LogoutValidatorResult result = validator.validate(null);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void validateRemovesMissingSignatureErrors() {
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
    void unsignedResponseSucceedsWithoutCallingDelegate() {
        Saml2LogoutResponse logoutResponse = mock(Saml2LogoutResponse.class);
        when(logoutResponse.getParameters()).thenReturn(Collections.emptyMap());
        Saml2LogoutResponseValidatorParameters parameters = mock(Saml2LogoutResponseValidatorParameters.class);
        when(parameters.getLogoutResponse()).thenReturn(logoutResponse);

        Saml2LogoutValidatorResult result = validator.validate(parameters);

        assertThat(result.hasErrors()).isFalse();
        verify(delegate, never()).validate(any());
    }
}