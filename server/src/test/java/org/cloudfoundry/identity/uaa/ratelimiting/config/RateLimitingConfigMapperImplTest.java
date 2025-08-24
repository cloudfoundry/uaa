package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.AbstractExceptionTestSupport;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWTjsonField;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigMapperImpl.CREDENTIAL_ID_NOT_FOUND_PREFIX;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigMapperImpl.DUPLICATE_NAME_PREFIX;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigMapperImpl.DUPLICATE_PATH_SELECTOR_PREFIX;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigMapperImpl.ERROR_IN_LIMITER_MAPPINGS_PREFIX;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigMapperImpl.LOGGING_OPTION_NOT_FOUND_PREFIX;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigMapperImpl.NO_NAME_PROVIDED_PREFIX;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.YamlConfigFileDTO.LimiterMap;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.YamlConfigFileDTO.YamlConfigFileDTOBuilder;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.YamlConfigFileDTO.builder;

class RateLimitingConfigMapperImplTest extends AbstractExceptionTestSupport {
    public static final LimiterMap LIMITER_MAP_All_all = LimiterMap.builder().name("All").global("1r/s").pathSelectors(List.of("all")).build();
    public static final LimiterMap LIMITER_MAP_AAA_all = LimiterMap.builder().name("AAA").withCallerCredentialsID("1r/s").pathSelectors(List.of("all")).build();
    public static final LimiterMap LIMITER_MAP_AAA_other = LimiterMap.builder().name("AAA").withCallerRemoteAddressID("1r/s").pathSelectors(List.of("other")).build();
    static final List<LimiterMap> MINIMAL_LIMITER_MAPPINGS = List.of(LIMITER_MAP_All_all);
    static final YamlConfigFileDTO MINIMAL_DTO = builder().limiterMappings(MINIMAL_LIMITER_MAPPINGS).build();
    static final YamlConfigFileDTO EMPTY_DTO = new YamlConfigFileDTO();

    NanoTimeSupplier currentTimeSupplier = new NanoTimeSupplier.Mock();

    private RateLimitingConfigMapperImpl createMapper(CredentialIdType... credentialIdTypes) {
        return new RateLimitingConfigMapperImpl(currentTimeSupplier, credentialIdTypes);
    }

    @Test
    void checkForCredentialIdTypes() {
        assertThat(new RateLimitingConfigMapperImpl().getCredentialIdTypeCount()).isZero();
        assertThat(new RateLimitingConfigMapperImpl(new CredentialIdTypeJWT(null)).getCredentialIdTypeCount()).isOne();
        assertThat(new RateLimitingConfigMapperImpl(new CredentialIdTypeJWT(null), new CredentialIdTypeJWTjsonField(null)).getCredentialIdTypeCount()).isEqualTo(2);
    }

    @Test
    void check_map_and_checkNoChange() {
        RateLimitingConfigMapperImpl mapper = createMapper();
        assertThat(mapper.dtoPrevious).isNull();
        assertThat(mapper.checkNoChange(null)).isTrue();
        assertThat(mapper.dtoPrevious).isNull();
        assertThat(mapper.checkNoChange(EMPTY_DTO)).isFalse();
        assertThat(mapper.dtoPrevious).isEqualTo(EMPTY_DTO); // cache Updated!
        assertThat(mapper.checkNoChange(EMPTY_DTO)).isTrue();
        assertThat(mapper.dtoPrevious).isEqualTo(EMPTY_DTO);

        assertThat(mapper.map(null, "test", null)).isNull();
        assertThat(mapper.map(null, "test", EMPTY_DTO)).isNull();
        assertThat(mapper.map(null, "test", MINIMAL_DTO)).isNotNull();
    }

    @Test
    void check_createSupplier_and_createErrorSupplierPair() {
        RateLimitingConfigMapperImpl mapper = createMapper();

        InternalLimiterFactoriesSupplier supplier = mapper.createSupplier(MINIMAL_DTO);
        assertThat(supplier).isNotNull();
        assertEquivalent(supplier, null, mapper.createErrorSupplierPair(MINIMAL_DTO));

        try {
            supplier = mapper.createSupplier(EMPTY_DTO);
            fail("Expected Exception, but got supplier: " + supplier);
        } catch (Exception e) {
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
                assertThat(actualStr).as(what + "s").isEqualTo(expectedStr);
            }
        }
    }

    @Test
    void checkForHappyCases() {
        RateLimitingConfigMapperImpl mapper = createMapper(new CredentialIdTypeJWT(null));
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
        assertThat(supplier.getLimiterMappings()).as(dto::toString).isEqualTo(mappings);
        assertThat(supplier.getLoggingOption()).as(dto::toString).isEqualTo(loggingOption);
        String description = supplier.getCallerCredentialsIdSupplierDescription();
        if (hasCallerCredentialsIdSupplierDescription) {
            assertThat(description).as(dto::toString).isNotNull();
        } else {
            assertThat(description).as(dto::toString).isEqualTo("None");
        }
    }

    @Test
    void validateErrorCases() {
        // Bad Credentials
        RateLimitingConfigMapperImpl mapper = createMapper(new CredentialIdTypeJWT(null));
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
        assertThat(dto.toString()).isNotNull();
        assertThat(mapper.toString()).isNotNull();
        assertThat(pair.hasError()).as(dto::toString).isTrue();
        assertThat(pair.getSupplier().isSupplierNOOP()).as(dto::toString).isTrue();
        assertThat(pair.getError()).as(dto::toString).isNotNull();
        String msg = pair.getErrorMsg();
        assertThat(msg).as(dto::toString).isNotNull();
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