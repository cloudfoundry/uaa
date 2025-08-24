package org.cloudfoundry.identity.statsd.integration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrationTestUtils {

    static final String UAA_BASE_URL = "http://localhost:8080/uaa";
    static final String TEST_USERNAME = "marissa";
    static final String TEST_PASSWORD = "koala";

    static void copyCookies(ResponseEntity<?> response, HttpHeaders headers) {
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }
    }

    static String extractCookieCsrf(String body) {
        String pattern = "\\<input type=\\\"hidden\\\" name=\\\"X-Uaa-Csrf\\\" value=\\\"(.*?)\\\"";

        Pattern linkPattern = Pattern.compile(pattern);
        Matcher matcher = linkPattern.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    static long getStatsDValueFromMessage(String message) {
        assertThat(message).isNotNull();

        String[] parts = message.split("[:|]");
        assertThat("g".equals(parts[2]) || "c".equals(parts[2])).isTrue();

        return Long.valueOf(parts[1]);
    }
}
