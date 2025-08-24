package org.cloudfoundry.identity.uaa.oauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaOauth2ErrorHandlerTests {

    private final Map<HttpStatus, ClientHttpResponse> responses = new HashMap<>();
    private UaaOauth2ErrorHandler handler;

    @BeforeEach
    void setUp() throws Exception {
        handler = new UaaOauth2ErrorHandler(null);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse r = mock(ClientHttpResponse.class);
            when(r.getStatusCode()).thenReturn(status);
            responses.put(status, r);
        }
    }

    @Test
    void test500Errors() throws Exception {
        handler.setErrorAtLevel(HttpStatus.Series.SERVER_ERROR);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse response = responses.get(status);
            if (status.is5xxServerError()) {
                assertThat(handler.hasError(response)).isTrue();
            } else {
                assertThat(handler.hasError(response)).isFalse();
            }
        }
    }

    @Test
    void test400_500Errors() throws Exception {
        handler.setErrorAtLevel(HttpStatus.Series.CLIENT_ERROR);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse response = responses.get(status);
            if (status.is5xxServerError() || status.is4xxClientError()) {
                assertThat(handler.hasError(response)).isTrue();
            } else {
                assertThat(handler.hasError(response)).isFalse();
            }
        }
    }

    @Test
    void setErrorLevel() {
        handler.setErrorAtLevel(HttpStatus.Series.SERVER_ERROR);
        assertThat(handler.getErrorAtLevel()).isEqualTo(HttpStatus.Series.SERVER_ERROR);
        handler.setErrorAtLevel(HttpStatus.Series.CLIENT_ERROR);
        assertThat(handler.getErrorAtLevel()).isEqualTo(HttpStatus.Series.CLIENT_ERROR);
    }

    @Test
    void setErrorLevelThroughConstructor() {
        handler = new UaaOauth2ErrorHandler(null, HttpStatus.Series.SERVER_ERROR);
        assertThat(handler.getErrorAtLevel()).isEqualTo(HttpStatus.Series.SERVER_ERROR);
        handler = new UaaOauth2ErrorHandler(null, HttpStatus.Series.CLIENT_ERROR);
        assertThat(handler.getErrorAtLevel()).isEqualTo(HttpStatus.Series.CLIENT_ERROR);
    }

}