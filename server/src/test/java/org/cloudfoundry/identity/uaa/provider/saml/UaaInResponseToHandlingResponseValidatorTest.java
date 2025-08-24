package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UaaInResponseToHandlingResponseValidatorTest {

    @Mock
    Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> delegate;

    @Mock
    OpenSaml4AuthenticationProvider.ResponseToken responseToken;

    @BeforeEach
    void beforeEach() {
        IdentityZoneHolder.clear();
    }

    @Test
    void delegateReturnsNullIsHandled() {
        when(delegate.convert(any())).thenReturn(null);
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator = new UaaInResponseToHandlingResponseValidator(delegate, true);

        assertThat(uaaInResponseToHandlingResponseValidator.convert(responseToken)).isNull();
    }

    @Test
    void delegateReturnsSuccessIsHandled() {
        Saml2ResponseValidatorResult success = Saml2ResponseValidatorResult.success();
        when(delegate.convert(any())).thenReturn(success);
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator = new UaaInResponseToHandlingResponseValidator(delegate, true);

        assertThat(uaaInResponseToHandlingResponseValidator.convert(responseToken)).isSameAs(success);
    }

    @Test
    void notDisabledPassesThru() {
        Saml2ResponseValidatorResult withErrors = Saml2ResponseValidatorResult.failure(new Saml2Error("invalid_in_response_to", "invalid_in_response_to"));
        when(delegate.convert(any())).thenReturn(withErrors);
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator = new UaaInResponseToHandlingResponseValidator(delegate, false);

        Saml2ResponseValidatorResult result = uaaInResponseToHandlingResponseValidator.convert(responseToken);
        assertThat(result).isSameAs(withErrors);
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .hasSize(1)
                .extracting(Saml2Error::getErrorCode)
                .containsExactly("invalid_in_response_to");
    }

    @Test
    void otherErrorsArePassedThru() {
        Saml2ResponseValidatorResult withErrors = Saml2ResponseValidatorResult.failure(new Saml2Error("other_error", "other_error"));
        when(delegate.convert(any())).thenReturn(withErrors);
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator = new UaaInResponseToHandlingResponseValidator(delegate, true);

        Saml2ResponseValidatorResult result = uaaInResponseToHandlingResponseValidator.convert(responseToken);

        // different instance, but the same content
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .hasSize(1)
                .extracting(Saml2Error::getErrorCode)
                .containsExactly("other_error");
    }

    @Test
    void inResponseToIsRemoved() {
        Saml2ResponseValidatorResult withErrors = Saml2ResponseValidatorResult.failure(new Saml2Error("invalid_in_response_to", "invalid_in_response_to"));
        when(delegate.convert(any())).thenReturn(withErrors);
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator = new UaaInResponseToHandlingResponseValidator(delegate, true);
        Saml2ResponseValidatorResult result = uaaInResponseToHandlingResponseValidator.convert(responseToken);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void otherZoneIsDisabledRemovesError() {
        setupIdentityZone(true);
        Saml2ResponseValidatorResult withErrors = Saml2ResponseValidatorResult.failure(new Saml2Error("invalid_in_response_to", "invalid_in_response_to"));
        when(delegate.convert(any())).thenReturn(withErrors);
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator = new UaaInResponseToHandlingResponseValidator(delegate, true);

        Saml2ResponseValidatorResult result = uaaInResponseToHandlingResponseValidator.convert(responseToken);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void otherZoneIsNotDisabledPassesThru() {
        setupIdentityZone(false);
        Saml2ResponseValidatorResult withErrors = Saml2ResponseValidatorResult.failure(new Saml2Error("invalid_in_response_to", "invalid_in_response_to"));
        when(delegate.convert(any())).thenReturn(withErrors);
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator = new UaaInResponseToHandlingResponseValidator(delegate, false);

        Saml2ResponseValidatorResult result = uaaInResponseToHandlingResponseValidator.convert(responseToken);
        assertThat(result).isSameAs(withErrors).returns(true, Saml2ResponseValidatorResult::hasErrors);
    }

    private static void setupIdentityZone(boolean disableInResponseToCheck) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId("testZone");
        identityZone.setConfig(new IdentityZoneConfiguration());
        identityZone.getConfig().setSamlConfig(new SamlConfig());
        identityZone.getConfig().getSamlConfig().setDisableInResponseToCheck(disableInResponseToCheck);
        IdentityZoneHolder.set(identityZone);
    }
}
