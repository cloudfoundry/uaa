package org.cloudfoundry.identity.uaa.oauth;

import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenEndpointBuilderTest {

    @Test
    void validatesIssuerBaseUrl() {
        assertThrows(MalformedURLException.class,
                () -> new TokenEndpointBuilder("not-a-url"));
    }

    @Test
    void acceptsValidUrls() {
        assertDoesNotThrow(() -> new TokenEndpointBuilder("http://some.page.online"));
    }

}