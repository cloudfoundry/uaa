package org.cloudfoundry.identity.uaa.oauth;


import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;

public class UaaOauth2ErrorHandlerTests {


    private Map<HttpStatus, ClientHttpResponse> responses = new HashMap<>();
    private UaaOauth2ErrorHandler handler = null;

    @Before
    public void setUp() throws Exception {
        handler = new UaaOauth2ErrorHandler(null);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse r = mock(ClientHttpResponse.class);
            when(r.getStatusCode()).thenReturn(status);
            responses.put(status, r);
        }
    }

    @Test
    public void test500Errors() throws Exception {
        handler.setErrorAtLevel(HttpStatus.Series.SERVER_ERROR);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse response = responses.get(status);
            if (status.is5xxServerError()) {
                Assert.assertTrue(handler.hasError(response));
            } else {
                Assert.assertFalse(handler.hasError(response));
            }
        }
    }

    @Test
    public void test400_500Errors() throws Exception {
        handler.setErrorAtLevel(HttpStatus.Series.CLIENT_ERROR);
        for (HttpStatus status : HttpStatus.values()) {
            ClientHttpResponse response = responses.get(status);
            if (status.is5xxServerError() || status.is4xxClientError()) {
                Assert.assertTrue(handler.hasError(response));
            } else {
                Assert.assertFalse(handler.hasError(response));
            }
        }
    }

    @Test
    public void testSetErrorLevel() {
        handler.setErrorAtLevel(HttpStatus.Series.SERVER_ERROR);
        Assert.assertEquals(HttpStatus.Series.SERVER_ERROR, handler.getErrorAtLevel());
        handler.setErrorAtLevel(HttpStatus.Series.CLIENT_ERROR);
        Assert.assertEquals(HttpStatus.Series.CLIENT_ERROR, handler.getErrorAtLevel());
    }

    @Test
    public void testSetErrorLevelThroughConstructor() {
        handler = new UaaOauth2ErrorHandler(null, HttpStatus.Series.SERVER_ERROR);
        Assert.assertEquals(HttpStatus.Series.SERVER_ERROR, handler.getErrorAtLevel());
        handler = new UaaOauth2ErrorHandler(null, HttpStatus.Series.CLIENT_ERROR);
        Assert.assertEquals(HttpStatus.Series.CLIENT_ERROR, handler.getErrorAtLevel());
    }

}