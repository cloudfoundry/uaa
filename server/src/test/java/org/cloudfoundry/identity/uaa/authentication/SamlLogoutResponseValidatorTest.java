package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
}