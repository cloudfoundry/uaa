package org.cloudfoundry.identity.uaa.oauth;

import java.util.Date;

/**
 * In the OpenId Connect spec, the auth_time claim is the number of seconds
 * from 1970-01-01T0:0:0Z as measured in UTC until the date/time. Since the
 * Date class uses number of milliseconds since 1970-01-01T0:0:0Z as measured
 * in UTC for its internal representation of time, we are frequently multiplying
 * and dividing by 1000 when converting between these representations.
 *
 * http://openid.net/specs/openid-connect-core-1_0.html#IDToken
 */
public class AuthTimeDateConverter {
    public static Date authTimeToDate(Long authTime) {
        if (null != authTime) {
            return new Date(authTime * 1000l);
        }
        return null;
    }

    public static Long dateToAuthTime(Date date) {
        if (null != date) {
            return date.getTime() / 1000;
        }
        return null;
    }
}
