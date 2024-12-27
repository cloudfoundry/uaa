package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.List;
import java.util.function.Function;

import org.cloudfoundry.identity.uaa.ratelimiting.AbstractExceptionTestSupport;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWTjsonField;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigMapperImpl.*;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.YamlConfigFileDTO.*;
import static org.junit.jupiter.api.Assertions.*;

class RateLimitingConfigMapperImplTest extends AbstractExceptionTestSupport {
    public static final LimiterMap LIMITER_MAP_All_all = LimiterMap.builder().name("All").global("1r/s").pathSelectors(List.of("all")).build();
    public static final LimiterMap LIMITER_MAP_AAA_all = LimiterMap.builder().name("AAA").withCallerCredentialsID("1r/s").pathSelectors(List.of("all")).build();
    public static final LimiterMap LIMITER_MAP_AAA_other = LimiterMap.builder().name("AAA").withCallerRemoteAddressID("1r/s").pathSelectors(List.of("other")).build();
    static final List<LimiterMap> MINIMAL_LIMITER_MAPPINGS = List.of(LIMITER_MAP_All_all);
    static final YamlConfigFileDTO MINIMAL_DTO = builder().limiterMappings(MINIMAL_LIMITER_MAPPINGS).build();
    static final YamlConfigFileDTO EMPTY_DTO = new YamlConfigFileDTO();

    NanoTimeSupplier currentTimeSupplier = new NanoTimeSupplier.Mock();

    private RateLimitingConfigMapperImpl createMapper(CredentialIdType... credentialIdTypes) {
        return new RateLimitingConfigMapperImpl( currentTimeSupplier, credentialIdTypes );
    }

    @Test
    void checkForCredentialIdTypes() {
        assertEquals(0, new RateLimitingConfigMapperImpl().getCredentialIdTypeCount());
        assertEquals(1, new RateLimitingConfigMapperImpl( new CredentialIdTypeJWT( null ) ).getCredentialIdTypeCount());
        assertEquals(2, new RateLimitingConfigMapperImpl( new CredentialIdTypeJWT( null ), new CredentialIdTypeJWTjsonField( null ) ).getCredentialIdTypeCount());
    }

    @Test
    void check_map_and_checkNoChange() {
        RateLimitingConfigMapperImpl mapper = createMapper();
        assertNull(mapper.dtoPrevious);
        assertTrue(mapper.checkNoChange(null));
        assertNull(mapper.dtoPrevious);
        assertFalse(mapper.checkNoChange(EMPTY_DTO));
        assertEquals(EMPTY_DTO, mapper.dtoPrevious); // cache Updated!
        assertTrue(mapper.checkNoChange(EMPTY_DTO));
        assertEquals(EMPTY_DTO, mapper.dtoPrevious);

        assertNull(mapper.map(null, "test", null));
        assertNull(mapper.map(null, "test", EMPTY_DTO));
        assertNotNull(mapper.map(null, "test", MINIMAL_DTO));
    }

    @Test
    void check_createSupplier_and_createErrorSupplierPair() {
        RateLimitingConfigMapperImpl mapper = createMapper();

        InternalLimiterFactoriesSupplier supplier = mapper.createSupplier(MINIMAL_DTO);
        assertNotNull(supplier);
        assertEquivalent(supplier, null, mapper.createErrorSupplierPair(MINIMAL_DTO));

        try {
            supplier = mapper.createSupplier(EMPTY_DTO);
            fail("Expected Exception, but got supplier: " + supplier);
        }
        catch (Exception e) {
            assertEquivalent(InternalLimiterFactoriesSupplier.NOOP, e, mapper.createErrorSupplierPair(EMPTY_DTO));
        }
    }

    private void assertEquivalent(InternalLimiterFactoriesSupplier supplier, Exception error, ErrorSupplierPair pair) {
        assertEquivalentStrings("error", error, pair.getError(), Exception::getMessage);
        assertEquivalentStrings("supplier", supplier, pair.getSupplier(), InternalLimiterFactoriesSupplier::toString);
    }

    private <T> void assertEquivalentStrings(String what, T expected, T actual, Function<T, String> toString) {
        if (expected != actual) {
            if (expected == null) {
                fail("Expected null, but actual " + what + " was: " + toString.apply(actual));
            } else if (actual == null) {
                fail("Actual " + what + " was null, but expected: " + toString.apply(expected));
            } else { // Neither 'null'
                String expectedStr = toString.apply(expected);
                String actualStr = toString.apply(actual);
                assertEquals(expectedStr, actualStr, what + "s");
            }
        }
    }

    @Test
    void checkForHappyCases() {
        RateLimitingConfigMapperImpl mapper = createMapper(new CredentialIdTypeJWT( null ));
        assertSupplier(false, LoggingOption.DEFAULT, 1, mapper, MINIMAL_DTO);
        assertSupplier(false, LoggingOption.AllCalls, 1, mapper,
                builder().limiterMappings(MINIMAL_LIMITER_MAPPINGS).loggingOption("AllCalls").build());
        assertSupplier(true, LoggingOption.DEFAULT, 1, mapper,
                builder().limiterMappings(MINIMAL_LIMITER_MAPPINGS).credentialID("JWT:claims").build());
        assertSupplier(false, LoggingOption.DEFAULT, 2, mapper,
                builder().limiterMappings(List.of(LIMITER_MAP_All_all, LIMITER_MAP_AAA_other)).build());
    }

    private void assertSupplier(boolean hasCallerCredentialsIdSupplierDescription, LoggingOption loggingOption, int mappings,
            RateLimitingConfigMapperImpl mapper, YamlConfigFileDTO dto) {
        InternalLimiterFactoriesSupplier supplier = mapper.createSupplier(dto);
        assertEquals(mappings, supplier.getLimiterMappings(), dto::toString);
        assertEquals(loggingOption, supplier.getLoggingOption(), dto::toString);
        String description = supplier.getCallerCredentialsIdSupplierDescription();
        if (hasCallerCredentialsIdSupplierDescription) {
            assertNotNull(description, dto::toString);
        } else {
            assertEquals("None", description, dto::toString);
        }
    }

    @Test
    void validateErrorCases() {
        // Bad Credentials
        RateLimitingConfigMapperImpl mapper = createMapper(new CredentialIdTypeJWT( null ));
        assertPairError(mapper, builder().limiterMappings(MINIMAL_LIMITER_MAPPINGS).credentialID("JWTspecial:claims"),
                CREDENTIAL_ID_NOT_FOUND_PREFIX);
        mapper = createMapper(); // No CredentialIdTypes
        assertPairError(mapper, builder().limiterMappings(MINIMAL_LIMITER_MAPPINGS).credentialID("JWT:claims"),
                CREDENTIAL_ID_NOT_FOUND_PREFIX);

        // Bad LoggingLevel
        assertPairError(mapper, builder().limiterMappings(MINIMAL_LIMITER_MAPPINGS).loggingOption("None"),
                LOGGING_OPTION_NOT_FOUND_PREFIX);

        // Bad LimiterMaps (between Maps)
        assertPairError(mapper, builder().limiterMappings(List.of(LimiterMap.builder().global("1r/s").build())),
                ERROR_IN_LIMITER_MAPPINGS_PREFIX, NO_NAME_PROVIDED_PREFIX);
        assertPairError(mapper, builder().limiterMappings(List.of(LIMITER_MAP_AAA_all, LIMITER_MAP_All_all)),
                ERROR_IN_LIMITER_MAPPINGS_PREFIX, DUPLICATE_PATH_SELECTOR_PREFIX);
        assertPairError(mapper, builder().limiterMappings(List.of(LIMITER_MAP_AAA_all, LIMITER_MAP_AAA_other)),
                ERROR_IN_LIMITER_MAPPINGS_PREFIX, DUPLICATE_NAME_PREFIX);
    }

    private void assertPairError(RateLimitingConfigMapperImpl mapper, YamlConfigFileDTOBuilder dtoBuilder,
            String expectedErrorStartsWithFragment, String... expectedErrorContainsFragments) {
        YamlConfigFileDTO dto = dtoBuilder.build();
        ErrorSupplierPair pair = mapper.createErrorSupplierPair(dto);
        assertNotNull(dto.toString());
        assertNotNull(mapper.toString());
        assertTrue(pair.hasError(), dto::toString);
        assertTrue(pair.getSupplier().isSupplierNOOP(), dto::toString);
        assertNotNull(pair.getError(), dto::toString);
        String msg = pair.getErrorMsg();
        assertNotNull(msg, dto::toString);
        if (!msg.startsWith(expectedErrorStartsWithFragment)) {
            fail("Expected \"" + msg + "\" to start with \"" + expectedErrorStartsWithFragment + "\", from: " + dto);
        }
        if ((expectedErrorContainsFragments != null) && (expectedErrorContainsFragments.length != 0)) {
            String subMsg = msg.substring(expectedErrorStartsWithFragment.length());
            for (String expectedErrorContainsFragment : expectedErrorContainsFragments) {
                int at = subMsg.indexOf(expectedErrorContainsFragment);
                if (at == -1) {
                    fail("Expected \"" + msg + "\" to contain \"" + expectedErrorContainsFragment + "\", from: " + dto);
                }
                subMsg = msg.substring(at + expectedErrorContainsFragment.length());
            }
        }
    }
}