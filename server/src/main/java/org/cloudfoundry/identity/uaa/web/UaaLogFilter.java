package org.cloudfoundry.identity.uaa.web;

import com.ge.predix.log.filter.LogFilter;

import org.slf4j.MDC;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Random;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UaaLogFilter extends LogFilter {
    static final String CORRELATION_HEADER_NAME = "X-B3-TraceId";
    static final String CORRELATION_KEY_NAME = "traceId";

    public UaaLogFilter(final LinkedHashSet<String> hostnames, final LinkedHashSet<String> zoneHeaders,
                        final String defaultZone) {
        super(hostnames, zoneHeaders, defaultZone);
    }

    public UaaLogFilter() {
        super();
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response, final FilterChain filterChain)
        throws ServletException, IOException {
        try {
            String correlationId = request.getHeader(CORRELATION_HEADER_NAME);
            setCorrelationId(StringUtils.hasText(correlationId) ? correlationId : Long.toHexString(new Random().nextLong()));

            super.doFilterInternal(request, response, filterChain);
        } finally {
            clearCorrelationId();
        }
    }

    void setCorrelationId(final String correlationId) {
        MDC.put(CORRELATION_KEY_NAME, correlationId);
     }

    private void clearCorrelationId() {
        MDC.remove(CORRELATION_KEY_NAME);
    }
}
