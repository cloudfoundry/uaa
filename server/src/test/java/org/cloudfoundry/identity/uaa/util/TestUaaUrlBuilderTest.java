package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class TestUaaUrlBuilderTest {
    private TestUaaUrlBuilder builder;

    @BeforeEach
    void setup() {
        builder = new TestUaaUrlBuilder();
        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com");
    }

    @Test
    void informativeError_whenNoSystemDomain() {
        ReflectionTestUtils.setField(builder, "systemDomain", "");
        assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> builder.build());
    }

    @Test
    void build_returnsUaaUrl() {
        String url = builder.build();
        assertThat(url).isEqualTo("https://uaa.foo.cf.com/");
    }

    @Test
    void setScheme_canChangeScheme() {
        String url = builder.withScheme("http").build();
        assertThat(url).isEqualTo("http://uaa.foo.cf.com/");
    }

    @Test
    void setPath_canAddPathStuff() {
        String url = builder.withPath("/oauth/authorize").build();
        assertThat(url).isEqualTo("https://uaa.foo.cf.com/oauth/authorize");
    }

    @Test
    void setSubdomain_canAddSubdomain() {
        String url = builder.withSubdomain("my-zone").build();
        assertThat(url).isEqualTo("https://my-zone.uaa.foo.cf.com/");
    }

    @Test
    void stringingItAllTogether() {
        String url = builder.withScheme("http")
                .withPath("/oauth/authorize")
                .withSubdomain("my-zone").build();
        assertThat(url).isEqualTo("http://my-zone.uaa.foo.cf.com/oauth/authorize");
    }

    @Test
    void handlesExtraSlashesProperly() {
        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com/");
        String url = builder.withPath("/oauth/authorize").build();
        assertThat(url).isEqualTo("https://uaa.foo.cf.com/oauth/authorize");

        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com/");
        String url2 = builder.withPath("oauth/authorize").build();
        assertThat(url2).isEqualTo("https://uaa.foo.cf.com/oauth/authorize");

        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com");
        String url3 = builder.withPath("oauth/authorize").build();
        assertThat(url3).isEqualTo("https://uaa.foo.cf.com/oauth/authorize");
    }
}
