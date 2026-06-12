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
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
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
class SamlLogoutResponseValidatorTest {

    @Mock
    private Saml2LogoutResponseValidator delegate;
    @Mock
    private Saml2LogoutResponseValidatorParameters parameters;
    @Mock
    private Saml2LogoutResponse logoutResponse;

    private SamlLogoutResponseValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SamlLogoutResponseValidator(delegate);
        when(parameters.getLogoutResponse()).thenReturn(logoutResponse);
    }

    @Nested
    class SignedRedirectViaDelegate {

        @BeforeEach
        void setUp() {
            when(logoutResponse.getBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
            when(logoutResponse.getParameters()).thenReturn(Map.of(Saml2ParameterNames.SIG_ALG, "rsa-sha256"));
        }

        @Test
        void validatePassesThruSuccess() {
            when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.success());
            assertThat(validator.validate(parameters).hasErrors()).isFalse();
        }

        @Test
        void validateRemovesMissingSignatureErrors() {
            Saml2Error signatureError = new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE, "Missing signature for object");
            when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.withErrors(signatureError).build());
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
    void unsignedRedirectResponseBypassesDelegateAndValidatesIssuerDestinationAndStatus() {
        String destination = "http://sp.example.com/saml/SingleLogout";
        String issuer = "http://idp.example.com";
        String xml = """
                <samlp:LogoutResponse
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    Destination="%s">
                  <saml:Issuer>%s</saml:Issuer>
                  <samlp:Status>
                    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
                  </samlp:Status>
                </samlp:LogoutResponse>
                """.formatted(destination, issuer);

        when(logoutResponse.getBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
        when(logoutResponse.getParameters()).thenReturn(Collections.emptyMap()); // no SigAlg
        when(logoutResponse.getSamlResponse()).thenReturn(Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml)));

        AssertingPartyMetadata party = mock(AssertingPartyMetadata.class);
        when(party.getEntityId()).thenReturn(issuer);
        RelyingPartyRegistration reg = mock(RelyingPartyRegistration.class);
        when(reg.getAssertingPartyMetadata()).thenReturn(party);
        when(reg.getSingleLogoutServiceResponseLocation()).thenReturn(destination);
        when(parameters.getRelyingPartyRegistration()).thenReturn(reg);

        Saml2LogoutValidatorResult result = validator.validate(parameters);

        assertThat(result.hasErrors()).isFalse();
        verify(delegate, never()).validate(any());
    }

    @Test
    void postBindingResponseUsesDelegate() {
        when(logoutResponse.getBinding()).thenReturn(Saml2MessageBinding.POST);
        when(delegate.validate(any())).thenReturn(Saml2LogoutValidatorResult.success());

        assertThat(validator.validate(parameters).hasErrors()).isFalse();
        verify(delegate).validate(parameters);
    }

    @Test
    void redirectResponseWithSignatureButNoSigAlgIsRejected() {
        when(logoutResponse.getBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
        when(logoutResponse.getParameters()).thenReturn(Map.of(Saml2ParameterNames.SIGNATURE, "somesig")); // Signature but no SigAlg

        Saml2LogoutValidatorResult result = validator.validate(parameters);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(e -> e.getErrorCode().equals(Saml2ErrorCodes.INVALID_SIGNATURE));
        verify(delegate, never()).validate(any());
    }
}
