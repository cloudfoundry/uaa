package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import static org.springframework.util.StringUtils.hasText;

public class SamlRedirectLogoutHandler implements LogoutSuccessHandler {
    private final LogoutSuccessHandler wrappedHandler;

    public SamlRedirectLogoutHandler(LogoutSuccessHandler wrappedHandler) {
        this.wrappedHandler = wrappedHandler;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        RequestWrapper requestWrapper = new RequestWrapper(request);
        String relayState = request.getParameter("RelayState");
        Map<String, String> params = null;
        try {
            if (hasText(relayState)) {
                if (UaaUrlUtils.isUrl(relayState)) {
                    params = Collections.singletonMap("redirect", relayState);
                } else {
                    params = JsonUtils.readValue(relayState, new TypeReference<Map<String, String>>() {});
                }
            }
        } catch (RuntimeException x) {
            //unable to parse RelayState
        }

        if (params != null) {
            String redirect = params.get("redirect");
            if (hasText(redirect)) {
                requestWrapper.setParameter("redirect", redirect);
            }
            String clientId = params.get("client_id");
            if (hasText(clientId)) {
                requestWrapper.setParameter("client_id", clientId);
            }
        }
        wrappedHandler.onLogoutSuccess(requestWrapper, response, authentication);
    }

    private static class RequestWrapper extends HttpServletRequestWrapper {
        private final Map<String, String[]> parameterMap;

        public RequestWrapper(HttpServletRequest request) {
            super(request);
            parameterMap = new HashMap<>(request.getParameterMap());
        }

        public void setParameter(String name, String... value) {
            parameterMap.put(name, value);
        }

        public String getParameter(String name) {
            String[] values = parameterMap.get(name);
            return values != null && values.length > 0 ? values[0] : null;
        }

        public Map<String, String[]> getParameterMap() {
            return parameterMap;
        }

        public Enumeration<String> getParameterNames() {
            return new Enumeration<String>() {
                Iterator<String> iterator = parameterMap.keySet().iterator();

                @Override
                public boolean hasMoreElements() {
                    return iterator.hasNext();
                }

                @Override
                public String nextElement() {
                    return iterator.next();
                }
            };
        }

        public String[] getParameterValues(String name) {
            return parameterMap.get(name);
        }

    }
}
