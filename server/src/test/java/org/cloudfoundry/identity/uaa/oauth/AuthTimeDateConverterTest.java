package org.cloudfoundry.identity.uaa.oauth;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class AuthTimeDateConverterTest {
    @Test
    void authTimeToDate_whenNull() {
        Date date = AuthTimeDateConverter.authTimeToDate(null);
        assertThat(date).isNull();
    }

    @Test
    void authTimeToDate_whenNotNull() {
        Date date = AuthTimeDateConverter.authTimeToDate(1L);
        assertThat(date).isEqualTo(new Date(1000L));
    }

    @Test
    void dateToAuthTime_whenNull() {
        Long authTime = AuthTimeDateConverter.dateToAuthTime(null);
        assertThat(authTime).isNull();
    }

    @Test
    void dateToAuthTime_whenNotNull() {
        long authTime = AuthTimeDateConverter.dateToAuthTime(new Date(1000L));
        assertThat(authTime).isOne();
    }
}