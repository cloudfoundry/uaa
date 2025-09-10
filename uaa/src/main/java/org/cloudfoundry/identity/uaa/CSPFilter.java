package org.cloudfoundry.identity.uaa;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class CSPFilter implements Filter, ApplicationContextInitializer<ConfigurableWebApplicationContext> {

    private String cspReportUri = "";

    @Override
    public void initialize(ConfigurableWebApplicationContext applicationContext) {
        ConfigurableEnvironment env = applicationContext.getEnvironment();
        String uri = env.getProperty("cspReportUri");
        if (uri != null && !uri.isEmpty()) {
            cspReportUri = uri;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Filter initialization if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        httpResponse.setHeader("Content-Security-Policy",
                "base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");

        httpResponse.setHeader(
                "Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';" +
                        "report-uri " + cspReportUri + ";"
        );

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Clean up resources if needed
    }
}