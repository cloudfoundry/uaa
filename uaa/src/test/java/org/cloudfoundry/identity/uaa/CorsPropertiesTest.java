package org.cloudfoundry.identity.uaa;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.ACCEPT_LANGUAGE;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_LANGUAGE;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

class CorsPropertiesTest {

    @EnableConfigurationProperties({CorsProperties.class, CorsProperties.DefaultAllowed.class, CorsProperties.XhrAllowed.class})
    static class TestCorsConfig {}

    private ApplicationContextRunner applicationContextRunner;

    @BeforeEach
    void setup() {
        applicationContextRunner = new ApplicationContextRunner().withUserConfiguration(TestCorsConfig.class);
    }
    @Test
    void whenCorsMaxAgePropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("cors.xhr.max_age=1000")
                .withPropertyValues("cors.default.max_age=1001")
                .run(context -> {
                    var properties = context.getBean(CorsProperties.class);
                    assertThat(properties.xhrMaxAge).isEqualTo(1000);
                    assertThat(properties.defaultMaxAge).isEqualTo(1001);
                });
    }

    @Test
    void whenCorsNoPropertiesAreSet() {
        applicationContextRunner
                .run(context -> {
                    var properties = context.getBean(CorsProperties.class);

                    assertThat(properties.enforceSystemZoneSettings).isFalse();

                    assertThat(properties.defaultAllowed.uris()).containsExactly(".*");
                    assertThat(properties.defaultAllowed.origins()).containsExactly(".*");
                    assertThat(properties.defaultAllowed.headers()).containsExactly(ACCEPT, AUTHORIZATION, CONTENT_TYPE, ACCEPT_LANGUAGE, CONTENT_LANGUAGE);
                    assertThat(properties.defaultAllowed.methods()).containsExactly("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH");
                    assertThat(properties.defaultAllowed.credentials()).isFalse();
                    assertThat(properties.defaultMaxAge).isEqualTo(1728000);

                    assertThat(properties.xhrAllowed.uris()).containsExactly(".*");
                    assertThat(properties.xhrAllowed.origins()).containsExactly(".*");
                    assertThat(properties.xhrAllowed.headers()).containsExactly(ACCEPT, AUTHORIZATION, CONTENT_TYPE, ACCEPT_LANGUAGE, CONTENT_LANGUAGE, "X-Requested-With");
                    assertThat(properties.xhrAllowed.methods()).containsExactly("GET", "OPTIONS");
                    assertThat(properties.xhrAllowed.credentials()).isTrue();
                    assertThat(properties.xhrMaxAge).isEqualTo(1728000);
                });
    }


    @Test
    void whenCorsPropertiesAreSet() {
        applicationContextRunner
                .withPropertyValues("cors.enforceSystemZonePolicyInAllZones=true")

                .withPropertyValues("cors.default.allowed.uris=uri1,uri2")
                .withPropertyValues("cors.default.allowed.origins=or1,or2,or3")
                .withPropertyValues("cors.default.allowed.headers=h1,h2,h3")
                .withPropertyValues("cors.default.allowed.methods=GET,PATCH,OPTIONS")
                .withPropertyValues("cors.default.allowed.credentials=true")
                .withPropertyValues("cors.default.max_age=1001")

                .withPropertyValues("cors.xhr.allowed.uris=xuri1,xuri2")
                .withPropertyValues("cors.xhr.allowed.origins=xor1,xor2,xor3")
                .withPropertyValues("cors.xhr.allowed.headers=xh1,xh2,xh3")
                .withPropertyValues("cors.xhr.allowed.methods=XGET,XPATCH,XOPTIONS")
                .withPropertyValues("cors.xhr.allowed.credentials=false")
                .withPropertyValues("cors.xhr.max_age=1002")

                .run(context -> {
                    var properties = context.getBean(CorsProperties.class);

                    assertThat(properties.enforceSystemZoneSettings).isTrue();

                    assertThat(properties.defaultAllowed.uris()).containsExactly("uri1", "uri2");
                    assertThat(properties.defaultAllowed.origins()).containsExactly("or1", "or2", "or3");
                    assertThat(properties.defaultAllowed.headers()).containsExactly("h1", "h2", "h3");
                    assertThat(properties.defaultAllowed.methods()).containsExactly("GET", "PATCH", "OPTIONS");
                    assertThat(properties.defaultAllowed.credentials()).isTrue();
                    assertThat(properties.defaultMaxAge).isEqualTo(1001);

                    assertThat(properties.xhrAllowed.uris()).containsExactly("xuri1", "xuri2");
                    assertThat(properties.xhrAllowed.origins()).containsExactly("xor1", "xor2", "xor3");
                    assertThat(properties.xhrAllowed.headers()).containsExactly("xh1", "xh2", "xh3");
                    assertThat(properties.xhrAllowed.methods()).containsExactly("XGET", "XPATCH", "XOPTIONS");
                    assertThat(properties.xhrAllowed.credentials()).isFalse();
                    assertThat(properties.xhrMaxAge).isEqualTo(1002);
                });
    }

}
