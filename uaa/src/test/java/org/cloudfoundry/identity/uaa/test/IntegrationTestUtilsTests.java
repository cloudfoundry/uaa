package org.cloudfoundry.identity.uaa.test;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.resolveRedirect;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class IntegrationTestUtilsTests {

    @ParameterizedTest
    @CsvSource({
            "http://localhost:8080/uaa/oauth/authorize, /uaa/login, http://localhost:8080/uaa/login",
            "http://localhost:8080/uaa/oauth/authorize, ../login, http://localhost:8080/uaa/login",
            "https://localhost:8443/uaa/oauth/authorize, /uaa/login, https://localhost:8443/uaa/login",
            "http://testzone1.localhost:8080/uaa/oauth/authorize, /uaa/login, http://testzone1.localhost:8080/uaa/login",
            "http://localhost:8080/uaa/zone/testzone1/oauth/authorize, /uaa/zone/testzone1/login, http://localhost:8080/uaa/zone/testzone1/login",
            "http://localhost:8080/uaa/oauth/authorize, https://client.example/callback?code=abc%2Bdef&state=a%26b, https://client.example/callback?code=abc%2Bdef&state=a%26b",
            "http://localhost:8080/uaa/oauth/authorize, //client.example/callback, http://client.example/callback",
            "http://localhost:8080/uaa/oauth/authorize, /uaa/?code=abc%2Bdef&state=a%26b, http://localhost:8080/uaa/?code=abc%2Bdef&state=a%26b",
            "http://localhost:8080/uaa/login.do, /uaa/oauth/authorize?response_type=code%20id_token&state=a%26b, http://localhost:8080/uaa/oauth/authorize?response_type=code%20id_token&state=a%26b",
            "http://localhost:8080/uaa/oauth/authorize, /app/#access_token=abc%2Bdef&code=xyz, http://localhost:8080/app/#access_token=abc%2Bdef&code=xyz"
    })
    void resolvesRedirectAgainstRequestUrl(String requestUrl, String location, String expectedUrl) {
        assertThat(resolveRedirect(requestUrl, URI.create(location))).isEqualTo(expectedUrl);
    }

    @ParameterizedTest
    @ValueSource(strings = {"token%20code", "token%20id_token%20code", "id_token%20code"})
    void followsHybridRedirectWithoutReencodingQuery(String responseType) {
        RestTemplate client = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(client).build();
        String location = "/uaa/oauth/authorize?response_type=" + responseType + "&state=a%26b%2Bc";
        String expectedUrl = "http://localhost:8080" + location;
        server.expect(requestTo(expectedUrl)).andRespond(withSuccess("approval", MediaType.TEXT_HTML));

        URI redirect = URI.create(resolveRedirect("http://localhost:8080/uaa/login.do", URI.create(location)));
        assertThat(client.exchange(redirect, HttpMethod.GET, HttpEntity.EMPTY, String.class).getBody())
                .isEqualTo("approval");

        server.verify();
    }

    @Test
    void missingLocationIdentifiesRequestUrl() {
        assertThatThrownBy(() -> resolveRedirect("http://localhost:8080/uaa/oauth/authorize", null))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("Location header from http://localhost:8080/uaa/oauth/authorize");
    }
}
