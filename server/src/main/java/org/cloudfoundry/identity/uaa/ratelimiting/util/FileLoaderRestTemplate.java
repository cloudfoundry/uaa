package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

// WebClient client = WebClient.create(); // WebClient dependency - not currently being pulled in!
public class FileLoaderRestTemplate implements FileLoader {
    private final String url;
    private final RestTemplate restTemplate;

    public FileLoaderRestTemplate( String url ) {
        this.url = url;
        restTemplate = new RestTemplate();
        restTemplate.setErrorHandler( new NoExceptionErrorHandler() );
    }

    @Override
    public String load()
            throws IOException {
        ResponseEntity<String> response = restTemplate.getForEntity( url, String.class );
        HttpStatus statusCode = response.getStatusCode();
        if ( statusCode != HttpStatus.OK ) {
            throw new IOException( "" + statusCode + " from: " + url );
        }
        return response.getBody();
    }

    @SuppressWarnings("NullableProblems")
    private static class NoExceptionErrorHandler implements ResponseErrorHandler {
        @Override
        public boolean hasError( ClientHttpResponse response ) {
            return false;
        }

        @Override
        public void handleError( ClientHttpResponse response ) {
            //ignore error
        }
    }
}
