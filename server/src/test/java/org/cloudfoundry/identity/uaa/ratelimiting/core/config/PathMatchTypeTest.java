package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("SameParameterValue")
class PathMatchTypeTest {

    @Test
    void options() {
        assertThat(PathMatchType.options()).isEqualTo("All, Other, Contains, StartsWith, or Equals");
    }

    @Test
    void pathUnacceptable() {
        checkStartsWithSlash(PathMatchType.Equals);
        checkStartsWithSlash(PathMatchType.StartsWith);
        checkNotEmpty(PathMatchType.Contains);
        checkEmpty(PathMatchType.Other);
        checkEmpty(PathMatchType.All);
    }

    private void checkStartsWithSlash(PathMatchType type) {
        assertThat(type.pathUnacceptable("/stuff")).as(type + ":/stuff").isNull();
        assertThat(type.pathUnacceptable("No-slash")).as(type + ":No-slash").isEqualTo("must start with a slash ('/')");
    }

    private void checkNotEmpty(PathMatchType type) {
        assertThat(type.pathUnacceptable("stuff")).as(type + ":stuff").isNull();
        assertThat(type.pathUnacceptable("")).as(type + ":").isEqualTo("must not be empty");
    }

    private void checkEmpty(PathMatchType type) {
        assertThat(type.pathUnacceptable("")).as(type + ":").isNull();
        assertThat(type.pathUnacceptable("Not-empty")).as(type + ":Not-empty").isEqualTo("must be empty");
    }
}