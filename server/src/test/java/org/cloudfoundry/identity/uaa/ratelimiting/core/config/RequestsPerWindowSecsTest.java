package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.*;

public class RequestsPerWindowSecsTest {
    private static final String NAME = "login";
    private static final String WHAT = "NoID";

    private void checkNull( String data ) {
        RequestsPerWindowSecs rpw = RequestsPerWindowSecs.from( NAME, WHAT, data );
        assertNull( rpw, "expected null from '" + data + "', but got: " + rpw );
    }

    private void checkOK( String data, int expectedRequests, int expectedWindow ) {
        RequestsPerWindowSecs rpw = RequestsPerWindowSecs.from( NAME, WHAT, data );
        assertNotNull( rpw, "null from '" + data + "'" );
        assertEquals( expectedRequests, rpw.getMaxRequestsPerWindow(), "requests from '" + data + "'" );
        assertEquals( expectedWindow, rpw.getWindowSecs(), "window from '" + data + "'" );
    }

    private void checkOK( int requests, int window ) {
        checkOK( RequestsPerWindowSecs.format( requests, window ), requests, window );
    }

    private void checkException( String data, String... exceptionMsgContains ) {
        RequestsPerWindowSecs rpw;
        try {
            rpw = RequestsPerWindowSecs.from( NAME, WHAT, data );
        }
        catch ( RateLimitingConfigException e ) {
            String msg = e.getMessage();
            int from = 0;
            for ( String fragment : exceptionMsgContains ) {
                int at = msg.indexOf( fragment, from );
                if ( at == -1 ) {
                    if ( from == 0 ) {
                        fail( "from '" + data + "' expect to find '" + fragment + "' in: '" + msg + "'" );
                    }
                    fail( "from '" + data + "' expect to find '" + fragment + "' in second part of: '" +
                          msg.substring( 0, from ) + "' + '" + msg.substring( from ) + "'" );
                }
                from = at + 1;
            }
            return;
        }
        assertNotNull( rpw, "null from '" + data + "'" );
        fail( "from '" + data + "' did NOT expect: '" + rpw + "'" );
    }

    private void checkException( int requests, int window, String... exceptionMsgContains ) {
        checkException( RequestsPerWindowSecs.format( requests, window ), exceptionMsgContains );
    }

    @Test
    public void nullReturns() {
        checkNull( null );
        checkNull( "" );
        checkNull( "  " ); // check data trimmed
    }

    @Test
    public void happyCasesVales() {
        // Extremes:
        checkOK( 0, 1 ); // block all calls (0 requests allowed)
        checkOK( 1, RequestsPerWindowSecs.MAX_WINDOW_SECONDS );
        checkOK( Integer.MAX_VALUE, 1 );

        // more common:
        checkOK( 5, 1 );
        checkOK( 10, 2 ); // supports bursting to 10 in 1st second but still no more than 5/s average
    }

    @Test
    public void happyCasesData() {
        checkOK( " 1r/2s ", 1, 2 ); // trimmed
        checkOK( "2R/3S", 2, 3 ); // ignores case
        checkOK( "15r/s", 15, 1 ); // default 1 sec
        checkOK( "60r/4s", 60, 4 );
        checkOK( Integer.MAX_VALUE + "r/5s", Integer.MAX_VALUE, 5 ); // parse of Max Value
    }

    @Test
    public void badValues() {
        checkException( -1, 1, RequestsPerWindowSecs.INVALID_REQUESTS_PREFIX, "be at least zero (0)" );
        checkException( 1, 0, RequestsPerWindowSecs.INVALID_WINDOW_PREFIX, "be at least (" + RequestsPerWindowSecs.MIN_WINDOW_SECONDS + ")" );
        checkException( 1, RequestsPerWindowSecs.MAX_WINDOW_SECONDS + 1, RequestsPerWindowSecs.INVALID_WINDOW_PREFIX, "must not exceed" );
    }

    @Test
    public void badFormats() {
        checkBadFormat( "r/1s" ); // NoRequests
        checkBadFormat( "r/s" ); // NoNumbers
        checkBadFormat( "5/2" ); // NoParseKeys
    }

    private void checkBadFormat( String data ) {
        checkException( data, RequestsPerWindowSecs.INVALID_FORMAT,
                        RequestsPerWindowSecs.formatOn( NAME, WHAT, data ) );
    }
}