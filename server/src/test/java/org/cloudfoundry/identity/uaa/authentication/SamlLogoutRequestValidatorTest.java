package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.provider.saml.Saml2Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.util.Collections;
import java.util.Map;

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
    @Mock
    private Saml2LogoutRequestValidatorParameters parameters;
    @Mock
    private Saml2LogoutRequest logoutRequest;

    private SamlLogoutRequestValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SamlLogoutRequestValidator(delegate);
        when(parameters.getLogoutRequest()).thenReturn(logoutRequest);
    }

    @Nested
    class SignedRedirectViaDelegate {

        @BeforeEach
        void setUp() {
            when(logoutRequest.getBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
            when(logoutRequest.getParameters()).thenReturn(Map.of(Saml2ParameterNames.SIG_ALG, "rsa-sha256"));
        }

        @Test
        void validatePassesThruSuccess() {
            when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.success());
            assertThat(validator.validate(parameters).hasErrors()).isFalse();
        }

        @Test
        void validateDifferentErrorIsPassedThru() {
            Saml2Error otherError = new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE, "Failed to match issuer to configured issuer");
            when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.withErrors(otherError).build());
            assertThat(validator.validate(parameters).hasErrors()).isTrue();
        }
    }

    @Test
    void unsignedRedirectRequestIsRejected() {
        when(logoutRequest.getBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
        when(logoutRequest.getParameters()).thenReturn(Collections.emptyMap()); // no SigAlg

        Saml2LogoutValidatorResult result = validator.validate(parameters);
        verify(delegate, never()).validate(any());

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .singleElement()
                .satisfies(e -> {
                    assertThat(e.getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_SIGNATURE);
                    assertThat(e.getDescription()).isEqualTo("Missing signature");
                });
    }

    @Test
    void postBindingRequestUsesDelegate() {
        when(logoutRequest.getBinding()).thenReturn(Saml2MessageBinding.POST);
        when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.success());

        assertThat(validator.validate(parameters).hasErrors()).isFalse();
        verify(delegate).validate(parameters);
    }

    @Test
    void redirectRequestWithSignatureButNoSigAlgIsRejected() {
        when(logoutRequest.getBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
        when(logoutRequest.getParameters()).thenReturn(Map.of(Saml2ParameterNames.SIGNATURE, "somesig")); // Signature but no SigAlg

        Saml2LogoutValidatorResult result = validator.validate(parameters);
        verify(delegate, never()).validate(any());

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .singleElement()
                .satisfies(e -> {
                    assertThat(e.getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_SIGNATURE);
                    assertThat(e.getDescription()).isEqualTo("Missing signature algorithm");
                });
    }
}
