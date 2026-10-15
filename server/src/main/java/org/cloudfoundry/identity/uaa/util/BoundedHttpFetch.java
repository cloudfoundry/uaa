package org.cloudfoundry.identity.uaa.util;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * Fetches a remote document with a hard limit on the number of body bytes read.
 * <p>
 * The request is sent through the template's {@link RestTemplate#getRequestFactory() request factory}, so TLS trust,
 * timeouts and SSRF protection of the template still apply. The template's error handler is deliberately bypassed:
 * Spring's default handler reads the complete 4xx/5xx body into memory, which would let an endpoint circumvent the
 * limit with an oversized error response. Errors are raised as the same {@link HttpClientErrorException} /
 * {@link HttpServerErrorException} types, carrying at most {@link #MAX_ERROR_BODY_BYTES} of the body.
 */
public final class BoundedHttpFetch {

    public static final String SIZE_EXCEEDED_MESSAGE = "Response exceeds maximum allowed size";
    public static final int MAX_ERROR_BODY_BYTES = 4 * 1024;

    private BoundedHttpFetch() {
    }

    /**
     * @param requestCallback prepares headers and body, e.g. {@link RestTemplate#httpEntityCallback(Object, java.lang.reflect.Type)}
     * @param requireOk       if true, any non-error status other than 200 is rejected with {@link IllegalArgumentException}
     * @return the body, never null (empty array for an empty body)
     * @throws IllegalArgumentException     if the body exceeds {@code maxBytes} or {@code requireOk} is violated
     * @throws HttpClientErrorException     on 4xx
     * @throws HttpServerErrorException     on 5xx
     * @throws ResourceAccessException      on I/O errors
     */
    public static byte[] fetch(RestTemplate template, URI uri, HttpMethod method, RequestCallback requestCallback,
            int maxBytes, boolean requireOk) {
        try {
            ClientHttpRequest request = template.getRequestFactory().createRequest(uri, method);
            if (requestCallback != null) {
                requestCallback.doWithRequest(request);
            }
            try (ClientHttpResponse response = request.execute()) {
                HttpStatusCode status = response.getStatusCode();
                if (status.isError()) {
                    byte[] errorBody = read(response.getBody(), MAX_ERROR_BODY_BYTES, false);
                    if (status.is4xxClientError()) {
                        throw HttpClientErrorException.create(status, response.getStatusText(), response.getHeaders(), errorBody, null);
                    }
                    throw HttpServerErrorException.create(status, response.getStatusText(), response.getHeaders(), errorBody, null);
                }
                if (requireOk && status.value() != HttpStatus.OK.value()) {
                    HttpStatus resolved = HttpStatus.resolve(status.value());
                    throw new IllegalArgumentException("Unable to fetch content, status:"
                            + (resolved != null ? resolved.getReasonPhrase() : status.value()));
                }
                if (response.getHeaders().getContentLength() > maxBytes) {
                    throw new IllegalArgumentException(SIZE_EXCEEDED_MESSAGE);
                }
                return read(response.getBody(), maxBytes, true);
            }
        } catch (IOException e) {
            throw new ResourceAccessException("I/O error on " + method + " request for \"" + uri + "\": " + e.getMessage(), e);
        }
    }

    private static byte[] read(InputStream body, int maxBytes, boolean failWhenExceeded) throws IOException {
        if (body == null) {
            return new byte[0];
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = body.read(buffer)) != -1) {
            if (total + read > maxBytes) {
                if (failWhenExceeded) {
                    throw new IllegalArgumentException(SIZE_EXCEEDED_MESSAGE);
                }
                out.write(buffer, 0, maxBytes - total);
                break;
            }
            total += read;
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
