package org.cloudfoundry.identity.uaa;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Configuration;

import java.util.List;

import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.ACCEPT_LANGUAGE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_LANGUAGE;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

@Configuration
@ConfigurationProperties
@EnableConfigurationProperties({CorsProperties.class, CorsProperties.DefaultAllowed.class, CorsProperties.XhrAllowed.class})
public class CorsProperties {

    @Value("${cors.enforceSystemZonePolicyInAllZones:false}") boolean enforceSystemZoneSettings;

    @Value("${cors.default.max_age:1728000}")
    int defaultMaxAge;
    @Value("${cors.xhr.max_age:1728000}")
    int xhrMaxAge;

    @Autowired
    DefaultAllowed defaultAllowed;
    @Autowired
    XhrAllowed xhrAllowed;

    @ConfigurationProperties(prefix = "cors.default.allowed")
    record DefaultAllowed(
        @DefaultValue({".*"}) List<String> uris,
        @DefaultValue({".*"}) List<String> origins,
        @DefaultValue({ACCEPT, AUTHORIZATION, CONTENT_TYPE, ACCEPT_LANGUAGE, CONTENT_LANGUAGE}) List<String> headers,
        @DefaultValue({"GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"}) List<String> methods,
        @DefaultValue("false") boolean credentials
    ) {}

    @ConfigurationProperties(prefix = "cors.xhr.allowed")
    record XhrAllowed(
            @DefaultValue({".*"}) List<String> uris,
            @DefaultValue({".*"}) List<String> origins,
            @DefaultValue({ACCEPT, AUTHORIZATION, CONTENT_TYPE, ACCEPT_LANGUAGE, CONTENT_LANGUAGE, "X-Requested-With"}) List<String> headers,
            @DefaultValue({"GET", "OPTIONS"}) List<String> methods,
            @DefaultValue("true") boolean credentials
    ) {}
}


