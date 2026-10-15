package org.cloudfoundry.identity.uaa.util;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Request factory for unit tests that serves scripted responses in order; the last step repeats.
 * Records every request so tests can assert on the number of remote fetches.
 */
public class StubClientHttpRequestFactory implements ClientHttpRequestFactory {

    private sealed interface Step permits Respond, Fail {
    }

    private record Respond(HttpStatus status, HttpHeaders headers, byte[] body) implements Step {
    }

    private record Fail(IOException exception) implements Step {
    }

    private final List<Step> steps = new ArrayList<>();
    private final List<MockClientHttpRequest> requests = new CopyOnWriteArrayList<>();

    public StubClientHttpRequestFactory respond(HttpStatus status, byte[] body) {
        return respond(status, new HttpHeaders(), body);
    }

    public StubClientHttpRequestFactory respond(HttpStatus status, HttpHeaders headers, byte[] body) {
        steps.add(new Respond(status, headers, body));
        return this;
    }

    public StubClientHttpRequestFactory fail(IOException exception) {
        steps.add(new Fail(exception));
        return this;
    }

    public List<MockClientHttpRequest> requests() {
        return requests;
    }

    public long requestCount(URI uri) {
        return requests.stream().filter(r -> uri.equals(r.getURI())).count();
    }

    @Override
    public synchronized ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
        if (steps.isEmpty()) {
            throw new IllegalStateException("No response scripted for " + httpMethod + " " + uri);
        }
        int index = Math.min(requests.size(), steps.size() - 1);
        MockClientHttpRequest request = new MockClientHttpRequest(httpMethod, uri);
        requests.add(request);
        Step step = steps.get(index);
        if (step instanceof Fail fail) {
            throw fail.exception();
        }
        Respond respond = (Respond) step;
        MockClientHttpResponse response = new MockClientHttpResponse(respond.body(), respond.status());
        response.getHeaders().putAll(respond.headers());
        request.setResponse(response);
        return request;
    }
}
