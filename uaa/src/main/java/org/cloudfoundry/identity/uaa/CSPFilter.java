package org.cloudfoundry.identity.uaa;

import org.springframework.core.env.Environment;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CSPFilter implements Filter {

    private String cspReportUri = "";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Step 1: Get the ServletContext
        ServletContext servletContext = filterConfig.getServletContext();

        // Step 2: Use WebApplicationContextUtils to get the Spring context
        WebApplicationContext springContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);

        if (springContext != null) {
            // Step 3: Access the Spring Environment object
            Environment env = springContext.getEnvironment();

            // Step 4: Retrieve the property value with fallbacks
            String uri = env.getProperty("cspReportUri",
                    System.getProperty("cspReportUri",
                            System.getenv("CSP_REPORT_URI")));

            if (uri != null && !uri.trim().isEmpty()) {
                this.cspReportUri = uri;
            }
        } else {
            // Handle the case where the Spring context is not yet available
            // Try system property first, then environment variable
            String uri = System.getProperty("cspReportUri", System.getenv("CSP_REPORT_URI"));

            if (uri != null && !uri.trim().isEmpty()) {
                this.cspReportUri = uri;
            }
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;


httpResponse.setHeader("Content-Security-Policy",
                       "base-uri 'self'; frame-ancestors 'none'; font-src 'self' https://cdn.predix-ui.com; img-src 'self'; frame-src 'self';");

        // Build report-uri part only if cspReportUri is not empty
        String reportUriPart = (cspReportUri != null && !cspReportUri.trim().isEmpty())
                ? "report-uri " + cspReportUri + ";"
                : "";

        // Set Content-Security-Policy-Report-Only header
        httpResponse.setHeader(
                "Content-Security-Policy-Report-Only",
                "default-src 'self';" +
                        "script-src 'self';" +
                        "style-src 'self';" +
                        "object-src 'none';" +
                        "form-action 'self';" +
                        reportUriPart
        );

        // Continue with the next filter in the chain
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Clean up resources if needed
    }
}