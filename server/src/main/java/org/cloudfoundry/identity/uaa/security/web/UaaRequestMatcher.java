package org.cloudfoundry.identity.uaa.security.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static org.cloudfoundry.identity.uaa.util.ObjectUtils.isEmpty;

/**
 * Custom request matcher which allows endpoints in the UAA to be matched as
 * substrings and also differentiation based
 * on the content type (e.g. JSON vs HTML) specified in the Accept request
 * header, thus allowing different filter chains
 * to be configured for browser and command-line clients.
 * <p>
 * Currently just looks for a match of the configured MIME-type in the accept
 * header when deciding whether to match the request. There is no parsing of
 * priorities in the header.
 */
public final class UaaRequestMatcher implements RequestMatcher, BeanNameAware {

    private static final Logger logger = LoggerFactory.getLogger(UaaRequestMatcher.class);

    private final String path;

    private List<String> accepts;

    private HttpMethod method;

    private Map<String, String> parameters = new HashMap<>();

    private final Map<String, List<String>> expectedHeaders = new HashMap<>();

    private String name;

    public UaaRequestMatcher(String path) {
        Assert.hasText(path, "must have text");
        if (path.contains("*")) {
            throw new IllegalArgumentException("UaaRequestMatcher is not intended for use with wildcards");
        }
        this.path = path;
    }

    /**
     * The HttpMethod that the request should be made with. Optional (if null,
     * then all values match)
     */
    public void setMethod(HttpMethod method) {
        this.method = method;
    }

    /**
     * A media type that should be present in the accept header for a request to
     * match. Optional (if null then all
     * values match).
     *
     * @param accepts the accept header value to set
     */
    public void setAccept(List<String> accepts) {
        this.accepts = Collections.unmodifiableList(accepts);
        setHeaders(Collections.singletonMap("accept", this.accepts));
    }

    /**
     * A map of request parameter name and values to match against. If all the
     * specified parameters are present and
     * match the values given then the accept header will be ignored.
     *
     * @param parameters the parameter matches to set
     */
    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String message = request.getRequestURI() + "'; '" + request.getContextPath() + path + "' with parameters="
                + parameters + " and headers " + expectedHeaders;
        if (logger.isTraceEnabled()) {
            logger.trace("[{}] Checking match of request : '{}", name, message);
        }

        if (!request.getRequestURI().startsWith(request.getContextPath() + path)) {
            return false;
        }

        if (method != null && !method.matches(request.getMethod().toUpperCase())) {
            return false;
        }

        for (Entry<String, List<String>> expectedHeaderEntry : expectedHeaders.entrySet()) {
            String requestValue = request.getHeader(expectedHeaderEntry.getKey());
            if ("accept".equalsIgnoreCase(expectedHeaderEntry.getKey())) {
                if (!matchesAcceptHeader(requestValue, expectedHeaderEntry.getValue())) {
                    return false;
                }
            } else if (!matchesHeader(requestValue, expectedHeaderEntry.getValue())) {
                return false;
            }
        }

        for (Entry<String, String> entry : parameters.entrySet()) {
            String value = request.getParameter(entry.getKey());
            if (value == null || !value.startsWith(entry.getValue())) {
                return false;
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("[{}]Matched request {}", name, message);
        }
        return true;
    }

    private boolean matchesHeader(String requestValue, List<String> expectedValues) {
        for (String headerValue : expectedValues) {
            if ("bearer".equalsIgnoreCase(headerValue.trim())) {
                //case insensitive for Authorization: Bearer match
                if (requestValue == null || !requestValue.toLowerCase().startsWith(headerValue)) {
                    return false;
                }
            } else if (requestValue == null || !requestValue.startsWith(headerValue)) {
                return false;
            }
        }
        return true;
    }

    private boolean matchesAcceptHeader(String requestValue, List<String> expectedValues) {
        // Accept header is not required to be checked!
        if (requestValue == null) {
            return true;
        }

        List<MediaType> requestValues = MediaType.parseMediaTypes(requestValue);
        if (isEmpty(requestValues)) {
            // the "Accept" header is set, but blank -> cannot match any expected value
            return false;
        }
        for (String expectedValue : expectedValues) {
            if (MediaType.parseMediaType(expectedValue).includes(requestValues.getFirst())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof UaaRequestMatcher other)) {
            return false;
        }
        if (!this.path.equals(other.path)) {
            return false;
        }

        if (!((this.method == null && other.method == null) || (this.method != null && other.method != null && this.method == other.method))) {
            return false;
        }

        if (!((this.parameters == null && other.parameters == null) || (this.parameters != null && this.parameters
                .equals(other.parameters)))) {
            return false;
        }

        if (!((this.accepts == null && other.accepts == null) || (this.accepts != null && this.accepts
                .equals(other.accepts)))) {
            return false;
        }

        return (this.expectedHeaders == null && other.expectedHeaders == null) || (this.expectedHeaders != null && this.expectedHeaders
                .equals(other.expectedHeaders));
    }

    @Override
    public int hashCode() {
        int code = 31 ^ path.hashCode();
        if (method != null) {
            code ^= method.hashCode();
        }
        if (accepts != null) {
            code ^= accepts.hashCode();
        }
        if (parameters != null) {
            code ^= parameters.hashCode();
        }
        return code;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UAAPath(").append(name).append(") ['").append(path).append("'");

        if (accepts != null) {
            sb.append(", ").append(accepts);
        }

        sb.append("]");

        return sb.toString();
    }

    public void setHeaders(Map<String, List<String>> headers) {
        for (Entry<String, List<String>> entry : headers.entrySet()) {
            List<String> expectedValues = new ArrayList<>(entry.getValue());
            expectedHeaders.put(entry.getKey(), expectedValues);
        }
    }

    @Override
    public void setBeanName(String name) {
        this.name = name;
    }
}
