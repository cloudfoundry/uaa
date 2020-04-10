package org.cloudfoundry.identity.statsd;

import org.slf4j.MDC;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Simple context listener that adds an MDC entry for the context path. Can be referenced using <code>%X{context}</code>
 * in a log4j format, like this:
 *
 * <pre>
 * [%d] %X{context} - [%t] %5p - %c{1}: %m%n
 * </pre>
 *
 * @author Dave Syer
 */
public class Log4jContextInitializer implements ServletContextListener, Filter {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        MDC.put("context", sce.getServletContext().getContextPath());
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        MDC.put("context", ((HttpServletRequest) request).getContextPath());
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("context");
        }
    }

    @Override
    public void destroy() {
    }

}
