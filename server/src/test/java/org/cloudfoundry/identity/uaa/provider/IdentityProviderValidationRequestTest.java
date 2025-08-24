package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest.UsernamePasswordAuthentication;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityProviderValidationRequestTest {

    @Test
    void noNPE() {
        UsernamePasswordAuthentication authentication = new UsernamePasswordAuthentication("user", null);
        assertThat(authentication.getPassword()).isNull();
    }
}