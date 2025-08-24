package org.cloudfoundry.identity.uaa.oauth;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatNoException;

class TokenEndpointBuilderTest {

    @Test
    void validatesIssuerBaseUrl() {
        assertThatExceptionOfType(MalformedURLException.class).isThrownBy(() -> new TokenEndpointBuilder("not-a-url"));
    }

    @Test
    void acceptsValidUrls() {
        assertThatNoException().isThrownBy(() -> new TokenEndpointBuilder("http://some.page.online"));
    }
}
