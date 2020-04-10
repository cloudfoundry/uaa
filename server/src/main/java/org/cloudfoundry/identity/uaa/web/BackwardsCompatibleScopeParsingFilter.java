
package org.cloudfoundry.identity.uaa.web;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.util.StringUtils;


public class BackwardsCompatibleScopeParsingFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        chain.doFilter(new ScopeRewriteRequestWrapper((HttpServletRequest)request), response);
    }

    @Override
    public void destroy() {

    }

    public class ScopeRewriteRequestWrapper extends HttpServletRequestWrapper {

        public ScopeRewriteRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getParameter(String name) {
            if ("scope".equals(name)) {
                return translateScope(super.getParameter(name));
            } else {
                return super.getParameter(name);
            }
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> map = super.getParameterMap();
            if (map.containsKey("scope")) {
                HashMap<String, String[]> result = new HashMap<>(map);
                result.put("scope", getParameterValues("scope"));
                map = result;
            }
            return map;
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] values = super.getParameterValues(name);
            if ("scope".equals(name)) {
                for (int i=0; values!=null && i<values.length; i++) {
                    values[i] = translateScope(values[i]);
                }
            }
            return values;
        }


        private String translateScope(String scope) {
            return StringUtils.hasText(scope) ? scope.replace(',', ' ') : scope;
        }
    }


}
