package org.cloudfoundry.identity.uaa.util;

public class TestUaaUrlBuilder {

    private String systemDomain;
    private String subdomain = "";
    private String path = "";
    private String scheme = "https";

    public TestUaaUrlBuilder() {
        systemDomain = System.getenv().get("TARGET_CF_SYSTEM_DOMAIN");
    }

    public String build() {
        if (systemDomain == null || "".equals(systemDomain)) {
            throw new RuntimeException("TARGET_CF_SYSTEM_DOMAIN environment variable must be set for tests to run. Example value: uaa-acceptance.cf-app.com");
        }

        systemDomain = systemDomain.replaceAll("/$", "");
        path = path.replaceAll("^/", "");

        String url;

        if (!"".equals(subdomain)) {
            url = "%s://%s.uaa.%s/%s".formatted(scheme, subdomain, systemDomain, path);
        } else {
            url = "%s://uaa.%s/%s".formatted(scheme, systemDomain, path);
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

    public String getSystemDomain() {
        systemDomain = systemDomain.replaceAll("/$", "");
        return systemDomain;
    }
}