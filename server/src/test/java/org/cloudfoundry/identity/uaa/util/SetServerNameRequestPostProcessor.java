package org.cloudfoundry.identity.uaa.util;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

public class SetServerNameRequestPostProcessor implements RequestPostProcessor {

    private final String serverName;

    public SetServerNameRequestPostProcessor(String serverName) {
        this.serverName = serverName;
    }

    @Override
    public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
        request.setServerName(serverName);
        return request;
    }
}
