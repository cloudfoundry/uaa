package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import static org.cloudfoundry.identity.uaa.ratelimiting.util.IntUtils.parseNoException;

import java.time.Duration;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;

import lombok.RequiredArgsConstructor;

public final class RequestsPerWindowSecs {
    public static final int MAX_WINDOW_SECONDS = (int) Duration.ofMinutes(30).toSeconds();
    static final int MIN_WINDOW_SECONDS = 1; // also the default
    static final String INVALID_REQUESTS_PREFIX = "Requests (before the 'r/') must ";
    static final String INVALID_WINDOW_PREFIX = "Window seconds (between the 'r/' and ending 's') must ";
    static final String INVALID_FORMAT = "Unacceptable format, expected ###r/[##]s, where '###' is the max requests, and '##' Window in seconds";

    /**
     * Defines the maximum requests to forward within the current time window (WindowSecs).
     *
     * @return non-negative number that indicates the initial maximum number of request to forward
     */
    public int getMaxRequestsPerWindow() {
        return maxRequestsPerWindow;
    }

    /**
     * Defines the duration of the current time window, where requests are tracked
     * to determine if any particular request is excessive relative to the max
     * requests threshold (MaxRequestsPerWindow).
     * <p>
     * Note: As there is a maximum value (see above MAX_WINDOW_SECONDS) supported,
     * if the configured vales exceeds the maximum, validation on construction will reject the configuration!
     *
     * @return positive number greater than or equal to the minimum defined above (MIN_WINDOW_SECONDS)
     */
    public int getWindowSecs() {
        return windowSecs;
    }

    public static RequestsPerWindowSecs from(String name, String what, String data) {
        data = StringUtils.stripToEmpty(data).toLowerCase();
        return data.isEmpty() ? null : new Parser( name, what, data ).parse();
    }

    // package friendly for testing
    static String formatOn(String name, String what, String data) {
        return "; on: " + name + " '" + what + "' from('" + data + "')";
    }

    private RequestsPerWindowSecs(int requests, int window) {
        maxRequestsPerWindow = requests;
        windowSecs = window;
    }

    private final int maxRequestsPerWindow;
    private final int windowSecs;

    @Override
    public String toString() {
        return format(maxRequestsPerWindow, windowSecs);
    }

    public static String format(int maxRequestsPerWindow, int windowSecs) {
        StringBuilder sb = new StringBuilder();
        sb.append(maxRequestsPerWindow).append("r/");
        if (windowSecs != 1) {
            sb.append(windowSecs);
        }
        sb.append('s');
        return sb.toString();
    }

    @RequiredArgsConstructor
    private static class Parser {
        private final String name;
        private final String what;
        private final String data;

        private void validateRequest(Integer requests) {
            if (requests < 0) {
                throw problem(INVALID_REQUESTS_PREFIX + "be at least zero (0), but got '" + requests + "'");
            }
        }

        private void validateWindow(Integer window) {
            if (window < MIN_WINDOW_SECONDS) {
                throw problem(INVALID_WINDOW_PREFIX + "be at least (" + MIN_WINDOW_SECONDS + "), but got '" + window + "'");
            }
            if (window > MAX_WINDOW_SECONDS) {
                throw problem(INVALID_WINDOW_PREFIX + "not exceed (" + MAX_WINDOW_SECONDS + "), but got '" + window + "'");
            }
        }

        public RequestsPerWindowSecs parse() {
            int at = data.indexOf("r/");
            if ((at != -1) && data.endsWith("s")) {
                Integer requests = parseNoException(data.substring(0, at), null);
                Integer window = parseNoException(data.substring(at + 2, data.length() - 1), MIN_WINDOW_SECONDS);
                if ((requests != null) && (window != null)) {
                    validateRequest(requests);
                    validateWindow(window);
                    return new RequestsPerWindowSecs( requests, window );
                }
            }
            throw problem(INVALID_FORMAT);
        }

        private RateLimitingConfigException problem(String text) {
            return new RateLimitingConfigException( text + formatOn(name, what, data) );
        }
    }
}
