package org.cloudfoundry.identity.uaa.ratelimiting.core;

import java.lang.reflect.Field;
import java.util.function.Consumer;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LoggingOptionTest {

    @Test
    void valueFor() {
        for ( LoggingOption value : LoggingOption.values() ) {
            check( value, Function.identity() );
            check( value, String::toLowerCase );
            check( value, String::toUpperCase );
        }
        assertNull( LoggingOption.valueFor( null ) );
        assertNull( LoggingOption.valueFor( "" ) );
        assertNull( LoggingOption.valueFor( " " + LoggingOption.AllCalls ) );
    }

    private void check( LoggingOption value, Function<String, String> nameMutator ) {
        String mutatedValueName = nameMutator.apply( value.name() );
        LoggingOption actual = LoggingOption.valueFor( value.name() );
        assertSame( value, actual, "mutated: " + mutatedValueName );
    }

    private static final CompoundKey TCK = CompoundKey.from( "T", "C", "K" );
    private static final String LTS = "LimiterToString";

    @Test
    void logNotLimited()
            throws Exception {
        String path = "!L";
        MockLimiter limiter = new MockLimiter( false, path );
        assertNull( limiter.execute( LoggingOption.OnlyLimited, 0 ) );
        check( limiter.execute( LoggingOption.AllCalls, 1 ),
               extract( LoggingOption.AllCalls, "PREFIX" ),
               path,
               extract( LoggingOption.AllCalls, "SUFFIX_CallsNotLimited" ),
               null );
        check( limiter.execute( LoggingOption.AllCallsWithDetails, 1 ),
               extract( LoggingOption.AllCallsWithDetails, "PREFIX" ),
               path,
               extract( LoggingOption.AllCallsWithDetails, "SUFFIX" ),
               LTS );
    }

    @Test
    void logLimited()
            throws Exception {
        String path = "L!";
        MockLimiter limiter = new MockLimiter( true, path );
        check( limiter.execute( LoggingOption.OnlyLimited, 1 ),
               extract( LoggingOption.OnlyLimited, "PREFIX" ),
               path,
               extract( LoggingOption.OnlyLimited, "SUFFIX" ),
               TCK.toString() );
        check( limiter.execute( LoggingOption.AllCalls, 1 ),
               extract( LoggingOption.AllCalls, "PREFIX" ),
               path,
               extract( LoggingOption.AllCalls, "SUFFIX_CallsLimited" ),
               TCK.toString() );
        check( limiter.execute( LoggingOption.AllCallsWithDetails, 1 ),
               extract( LoggingOption.AllCallsWithDetails, "PREFIX" ),
               path,
               extract( LoggingOption.AllCallsWithDetails, "SUFFIX" ),
               LTS );
    }

    private static class MockLimiter implements Limiter {
        private final boolean shouldLimit;
        private final String requestPath;

        public MockLimiter( boolean shouldLimit, String requestPath ) {
            this.shouldLimit = shouldLimit;
            this.requestPath = requestPath;
        }

        @Override
        public boolean shouldLimit() {
            return shouldLimit;
        }

        @Override
        public CompoundKey getLimitingKey() {
            return TCK;
        }

        @Override
        public String toString() {
            return LTS;
        }

        private String execute( LoggingOption option, int expectedCalls ) {
            MockLogger logger = new MockLogger();
            option.log( requestPath, logger, this );
            assertEquals( expectedCalls, logger.calls, requestPath + ":" + option );
            return logger.value;
        }
    }

    private static class MockLogger implements Consumer<String> {
        String value;
        int calls = 0;

        @Override
        public void accept( String value ) {
            this.value = value;
            calls++;
        }
    }

    private static void check( String actual, String prefix, String path, String suffix, String suffixPlus ) {
        String expected = prefix + " '" + path + "' " + suffix + (suffixPlus == null ? "" : (" " + suffixPlus));
        assertEquals( expected, actual );
    }

    private static String extract( Object o, String staticStringFieldName )
            throws Exception {
        Class<?> klass = o.getClass();
        Field field = klass.getField( staticStringFieldName );
        Object value = field.get( null );
        return (String)value;
    }
}