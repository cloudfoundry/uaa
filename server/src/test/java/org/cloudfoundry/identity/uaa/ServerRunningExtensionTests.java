package org.cloudfoundry.identity.uaa;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestOperations;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.FOUND;

class ServerRunningExtensionTests {

    @ParameterizedTest
    @CsvSource({
            "/uaa, /login.do, /uaa/oauth/authorize, http://testzone1.localhost:8080/uaa/oauth/authorize",
            "/uaa, /login.do, oauth/authorize, http://testzone1.localhost:8080/uaa/oauth/authorize",
            "/uaa/zone/testzone1, /login.do, /uaa/zone/testzone1/oauth/authorize, http://testzone1.localhost:8080/uaa/zone/testzone1/oauth/authorize",
            "/uaa, /login.do, https://client.example/callback?code=abc%2Bdef, https://client.example/callback?code=abc%2Bdef"
    })
    void followsRedirectAgainstLoginRequest(String rootPath, String requestPath, String location, String expectedUrl) {
        ServerRunningExtension serverRunning = ServerRunningExtension.connect();
        serverRunning.setHostName("testzone1.localhost");
        serverRunning.setPort(8080);
        serverRunning.setRootPath(rootPath);
        RestOperations client = mock(RestOperations.class);
        serverRunning.setRestTemplate(client);

        ResponseEntity<Void> redirect = ResponseEntity.status(FOUND).location(URI.create(location)).build();
        ResponseEntity<Void> response = ResponseEntity.ok().build();
        when(client.exchange(eq(serverRunning.getUrl(requestPath)), eq(POST), any(HttpEntity.class), eq(Void.class)))
                .thenReturn(redirect);
        when(client.exchange(eq(URI.create(expectedUrl)), eq(GET), any(HttpEntity.class), eq(Void.class)))
                .thenReturn(response);

        assertThat(serverRunning.postForRedirect(requestPath, new HttpHeaders(), new LinkedMultiValueMap<>()))
                .isSameAs(response);
        verify(client).exchange(eq(URI.create(expectedUrl)), eq(GET), any(HttpEntity.class), eq(Void.class));
    }
}
