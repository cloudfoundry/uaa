package org.cloudfoundry.identity.uaa.oauth.provider.error;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultWebResponseExceptionTranslatorTests {
    private final WebResponseExceptionTranslator<OAuth2Exception> translator = new DefaultWebResponseExceptionTranslator();

    @Test
    void translateWhenGeneralExceptionThenReturnInternalServerError() throws Exception {
        String errorMessage = "An error message that contains sensitive information that should not be exposed to the caller.";
        ResponseEntity<OAuth2Exception> response = this.translator.translate(new Exception(errorMessage));
        assertThat(response.getBody().getMessage()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
    }
}
