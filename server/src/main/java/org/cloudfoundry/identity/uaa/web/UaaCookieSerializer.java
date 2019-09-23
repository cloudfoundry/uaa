package org.cloudfoundry.identity.uaa.web;

import org.springframework.session.web.http.DefaultCookieSerializer;

public class UaaCookieSerializer extends DefaultCookieSerializer {
    public UaaCookieSerializer() {
        super();
        setSameSite(null);
    }
}
