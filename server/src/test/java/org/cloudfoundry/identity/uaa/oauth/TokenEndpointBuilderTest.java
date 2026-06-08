package org.cloudfoundry.identity.uaa.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenEndpointBuilderTest {

    @Test
    void validatesIssuerBaseUrl() {
        assertThatThrownBy(() -> new TokenEndpointBuilder("not-a-url")).asInstanceOf(InstanceOfAssertFactories.throwable(MalformedURLException.class));
    }

    @Test
    void acceptsValidUrls() {
        assertThatNoException().isThrownBy(() -> new TokenEndpointBuilder("http://some.page.online"));
    }
}
