package org.cloudfoundry.identity.uaa.util;

import org.springframework.beans.factory.annotation.Value;

public class TestUaaUrlBuilder {

    @Value("TARGET_CF_SYSTEM_DOMAIN")
    private String systemDomain;
    private String subdomain = "";
    private String path = "";
    private String scheme = "https";

    public String build() {
        if (systemDomain == null || "".equals(systemDomain)) {
            throw new RuntimeException("TARGET_CF_SYSTEM_DOMAIN environment variable must be set for tests to run. Example value: oms.identity.team");
        }

        systemDomain = systemDomain.replaceAll("/$","");
        path = path.replaceAll("^/", "");

        String url;

        if (!"".equals(subdomain)) {
            url = String.format("%s://%s.uaa.%s/%s", scheme, subdomain, systemDomain, path);
        } else {
            url = String.format("%s://uaa.%s/%s", scheme, systemDomain, path);
        }

        return url;
    }

    public TestUaaUrlBuilder withScheme(String scheme) {
        this.scheme = scheme;
        return this;
    }

    public TestUaaUrlBuilder withPath(String path) {
        this.path = path;
        return this;
    }

    public TestUaaUrlBuilder withSubdomain(String subdomain) {
        this.subdomain = subdomain;
        return this;
    }
}
