package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.IOException;
import java.time.Instant;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

import org.cloudfoundry.identity.uaa.ratelimiting.AbstractExceptionTestSupport;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterFactorySupplierUpdatable;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.Fetcher;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.LoaderLogger;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigLoader.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@SuppressWarnings("SameParameterValue")
public class RateLimitingConfigLoaderTest extends AbstractExceptionTestSupport {
    private static class SupplierUpdatable implements LimiterFactorySupplierUpdatable {
        RateLimitingFactoriesSupplierWithStatus lfs;

        @Override
        public void update( @Nonnull RateLimitingFactoriesSupplierWithStatus factoriesSupplierWithStatus ) {
            lfs = factoriesSupplierWithStatus;
        }
    }

    MillisTimeSupplier currentTimeSupplier = new MillisTimeSupplier.Mock( Instant.parse( "2011-01-15T12:34:56Z" ) );

    LoaderLogger logger = Mockito.mock( LoaderLogger.class );

    Fetcher fetcher = Mockito.mock( Fetcher.class );

    SupplierUpdatable supplierUpdatable = new SupplierUpdatable();

    private RateLimitingConfigLoader createLoader() {
        RateLimitingFactoriesSupplierWithStatus current = RateLimitingFactoriesSupplierWithStatus.builder()
                .supplier( InternalLimiterFactoriesSupplier.NOOP )
                .status( RateLimiterStatus.NO_RATE_LIMITING )
                .build();
        return new RateLimitingConfigLoader( logger, fetcher, "Out-There",
                                             new RateLimitingConfigMapperImpl( true, currentTimeSupplier ),
                                             current, supplierUpdatable, currentTimeSupplier, true );
    }

    @Test
    void checkForUpdate_BadYaml()
            throws IOException {
        RateLimitingConfigLoader loader = createLoader();

        when( fetcher.fetchYaml() ).thenThrow( new IOException( "Whatever" ) );
        assertTrue( loader.checkForUpdate() );
        assertEquals( "", loader.getLastYAML() );
        assertEquals( YamlRateLimitingConfigException.MESSAGE_PREFIX + YAML_FETCH_FAILED,
                      supplierUpdatable.lfs.getStatus().getUpdate().getError(),
                      supplierUpdatable.lfs::getStatusJson );
    }

    @Test
    void checkForUpdate_ParseErrors()
            throws IOException {
        RateLimitingConfigLoader loader = createLoader();

        when( fetcher.fetchYaml() ).thenReturn( "Fred: Wilma" );
        assertTrue( loader.checkForUpdate() );
        assertEquals( "Fred: Wilma", loader.getLastYAML() );
        assertStartsWith( YamlRateLimitingConfigException.MESSAGE_PREFIX + "Out-There: Cannot create property=Fred",
                          supplierUpdatable.lfs.getStatus().getUpdate().getError(),
                          supplierUpdatable.lfs::getStatusJson );

        assertFalse( loader.checkForUpdate() ); // Same String == NO Update!
    }

    @Test
    void checkForUpdate_UpdatedNoError()
            throws IOException {
        RateLimitingConfigLoader loader = createLoader();

        String[] yamlLines = {
                "limiterMappings:",
                "- name: ALL",
                "  global: 150r/s",
                "  pathSelectors:",
                "  - 'all'",
                ""
        };
        String yaml = String.join( "\n", yamlLines );

        when( fetcher.fetchYaml() ).thenReturn( yaml );
        assertTrue( loader.checkForUpdate() );
        assertEquals( yaml, loader.getLastYAML() );

        String[] expectedLines = {
                "{",
                "  'current' : {",
                "    'status' : 'ACTIVE',",
                "    'asOf' : '2011-01-15T12:34:56Z',",
                "    'credentialIdExtractor' : 'None',",
                "    'loggingLevel' : 'OnlyLimited',",
                "    'limiterMappings' : 1",
                "  },",
                "  'update' : {",
                "    'status' : 'PENDING'",
                "  },",
                "  'fromSource' : 'Out-There'",
                "}"
        };
        assertEquals( String.join( "\n", expectedLines ).replace( '\'', '"' ),
                      supplierUpdatable.lfs.getStatusJson() );
    }

    @Test
    void loadYamlString()
            throws IOException {
        RateLimitingConfigLoader loader = createLoader();

        String value = "Fred: Wilma";
        when( fetcher.fetchYaml() )
                .thenThrow( new IOException( "Whatever" ) ) // this order must match the order of the calls!
                .thenReturn( value
                        , null
                        , "  "
                        , "---"
                );
        // this order must match the order of the "then's" above!
        expectExceptionLoadYamlString( loader, YAML_FETCH_FAILED );
        assertEquals( value, loader.loadYamlString() );
        expectExceptionLoadYamlString( loader, YAML_NULL );
        expectExceptionLoadYamlString( loader, YAML_EMPTY );
        expectExceptionLoadYamlString( loader, YAML_NO_DATA );
    }

    private void expectExceptionLoadYamlString( RateLimitingConfigLoader loader, String yamlErrorText ) {
        String className = YamlRateLimitingConfigException.class.getSimpleName();
        try {
            String result = loader.loadYamlString();
            fail( "expected Exception (" + className + "), but got result of: " + result );
        }
        catch ( YamlRateLimitingConfigException expected ) {
            assertEquals( YamlRateLimitingConfigException.MESSAGE_PREFIX + yamlErrorText, expected.getMessage() );
        }
    }

    static void assertStartsWith( String expected, String actual, Supplier<String> messageSupplier ) {
        if ( (expected == null) || expected.isEmpty() ) {
            throw new Error( "expected null or empty!" );
        }
        if ( actual == null ) {
            fail( "'actual' null" );
        }
        if ( !actual.startsWith( expected ) ) {
            String suffix = StringUtils.normalizeToEmpty( (messageSupplier == null) ? "" : messageSupplier.get() );
            fail( "actual did NOT start with expected:"
                  + "\n  expected '" + expected + "'"
                  + "\n    actual '" + actual + "'"
                  + "\n   context:\n" + suffix );
        }
    }
}