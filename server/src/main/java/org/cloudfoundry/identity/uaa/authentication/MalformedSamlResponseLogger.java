package org.cloudfoundry.identity.uaa.authentication;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// Using SamlResponseLoggerBinding for any backward compatibility issues
@Slf4j(topic = "org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding")
@Component("samlResponseLoggerBinding")
public class MalformedSamlResponseLogger {
    public static final String X_VCAP_REQUEST_ID_HEADER = "X-Vcap-Request-Id";

    public void logMalformedResponse(HttpServletRequest httpServletRequest) {
        log.warn("Malformed SAML response. More details at log level DEBUG.");

        if (httpServletRequest == null) {
            log.debug("HttpServletRequest is null - no information to log");
            return;
        }

        if (!log.isDebugEnabled()) {
            // Logger is not in debug mode, so we don't need to log the details
            return;
        }

        log.debug("Method: {}, Params (name/size): {}, Content-type: {}, Request-size: {}, {}: {}",
                httpServletRequest.getMethod(),
                describeParameters(httpServletRequest),
                httpServletRequest.getContentType(),
                httpServletRequest.getContentLength(),
                X_VCAP_REQUEST_ID_HEADER,
                httpServletRequest.getHeader(X_VCAP_REQUEST_ID_HEADER));
    }

    private static String describeParameters(HttpServletRequest t) {
        if (t == null || t.getParameterMap() == null) {
            return null;
        }

        return t.getParameterMap()
                .entrySet()
                .stream()
                .map(MalformedSamlResponseLogger::formatParam)
                .collect(Collectors.joining(" "));
    }

    private static String formatParam(Map.Entry<String, String[]> p) {
        if (p == null) {
            return "(UNKNOWN/0)";
        }

        if (p.getValue() == null) {
            return String.format("(%s/0)", p.getKey());
        }

        List<String> formattedParams = new ArrayList<>(p.getValue().length);

        for (String val : p.getValue()) {
            formattedParams.add(String.format("(%s/%s)", p.getKey(), val == null ? 0 : val.length()));
        }

        return String.join(" ", formattedParams);
    }
}
