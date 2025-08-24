package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UaaLoginHintTest {

    @Test
    void parseHintNull() {
        assertThat(UaaLoginHint.parseRequestParameter(null)).isNull();
    }

    @Test
    void parseHintOrigin() {
        UaaLoginHint hint = UaaLoginHint.parseRequestParameter("{\"origin\":\"ldap\"}");
        assertThat(hint).isNotNull();
        assertThat(hint.getOrigin()).isEqualTo("ldap");
    }
}
