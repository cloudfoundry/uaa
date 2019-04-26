package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Test;

import java.net.MalformedURLException;

public class TokenEndpointBuilderTest {
    @Test(expected = MalformedURLException.class)
    public void validatesIssuerBaseUrl() throws Exception {
        new TokenEndpointBuilder("not-a-url");
    }

    @Test
    public void acceptsValidUrls() throws Exception {
        new TokenEndpointBuilder("http://some.page.online");
    }

}