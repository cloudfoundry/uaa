package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CorsPolicy {

    private CorsConfiguration xhrConfiguration = new CorsConfiguration();

    private CorsConfiguration defaultConfiguration = new CorsConfiguration();

    public CorsConfiguration getXhrConfiguration() {
        return xhrConfiguration;
    }

    public CorsPolicy setXhrConfiguration(CorsConfiguration xhrConfiguration) {
        this.xhrConfiguration = xhrConfiguration;
        return this;
    }

    public CorsConfiguration getDefaultConfiguration() {
        return defaultConfiguration;
    }

    public CorsPolicy setDefaultConfiguration(CorsConfiguration defaultConfiguration) {
        this.defaultConfiguration = defaultConfiguration;
        return this;
    }

}
