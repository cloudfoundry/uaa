package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Test;

import java.util.Date;

import static org.junit.Assert.*;

public class AuthTimeDateConverterTest {
    @Test
    public void authTimeToDate_whenNull() {
        Date date = AuthTimeDateConverter.authTimeToDate(null);
        assertNull(date);
    }

    @Test
    public void authTimeToDate_whenNotNull() {
        Date date = AuthTimeDateConverter.authTimeToDate(1l);
        assertEquals(new Date(1000l), date);
    }

    @Test
    public void dateToAuthTime_whenNull() {
        Long authTime = AuthTimeDateConverter.dateToAuthTime(null);
        assertNull(authTime);
    }

    @Test
    public void dateToAuthTime_whenNotNull() {
        long authTime = AuthTimeDateConverter.dateToAuthTime(new Date(1000l));
        assertEquals(1, authTime);
    }
}