package org.cloudfoundry.identity.uaa.ratelimiting.internal;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings({"SameParameterValue"})
class RateLimiterStatusTest {
    private static final long NOW_15_123450 = Instant.parse("2011-01-15T12:34:50Z").toEpochMilli();
    private static final long NOW_15_123456 = Instant.parse("2011-01-15T12:34:56Z").toEpochMilli();
    private static final long NOW_16_012345 = Instant.parse("2011-01-16T01:23:45Z").toEpochMilli();
    private static final long NOW_16_014000 = Instant.parse("2011-01-16T01:40:00Z").toEpochMilli();

    @Test
    void statusVariation_CompletelyDisabled() {
        check(createCompletelyDisabled(NOW_15_123456), // Example of Rate Limiting completely Disabled!
                "{",
                "  'current' : {",
                "    'status' : 'DISABLED',",
                "    'asOf' : '" + toISO(NOW_15_123456) + "'",
                "  }",
                "}");
    }

    @Test
    void statusVariation_WithLocalFileOnly() {
        check(createInitialFileOnlySuccess(NOW_15_123456),
                "{",
                "  'current' : {",
                "    'status' : 'ACTIVE',",
                "    'asOf' : '" + toISO(NOW_15_123456) + "',",
                "    'credentialIdExtractor' : 'JWT[1]',",
                "    'loggingLevel' : 'OnlyLimited',",
                "    'limiterMappings' : 9",
                "  },",
                "  'fromSource' : 'Local Config File'",
                "}");

        check(createInitialFileOnlyError(NOW_15_123456),
                "{",
                "  'current' : {",
                "    'status' : 'DISABLED',",
                "    'asOf' : '" + toISO(NOW_15_123456) + "',",
                "    'error' : 'someError'",
                "  },",
                "  'fromSource' : 'Local Config File'",
                "}");
    }

    @Test
    void statusVariation_WithDynamicURLUpdateOnly() {
        long time1 = NOW_15_123456; // Times for a time-based sequence
        long time6 = NOW_16_014000;

        RateLimiterStatus status = createInitialUrlBased(time1);
        check(status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and waiting for update!
                "{",
                "  'current' : {",
                "    'status' : 'DISABLED',",
                "    'asOf' : '" + toISO(time1) + "'",
                "  },",
                "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
                "}");

        check(updateSucceeded(status, time6), // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where update succeeded!
                "{",
                "  'current' : {",
                "    'status' : 'ACTIVE',",
                "    'asOf' : '" + toISO(time6) + "',",
                "    'credentialIdExtractor' : 'JWT[1]',",
                "    'loggingLevel' : 'OnlyLimited',",
                "    'limiterMappings' : 9",
                "  },",
                "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
                "}");
    }

    @Test
    void statusVariation_WithLocalFile_AND_WithDynamicURLUpdate() {
        long time1 = NOW_15_123450; // Times for a time-based sequence
        long time6 = NOW_16_014000;

        RateLimiterStatus status = createInitialFile_AND_UrlBased(time1);
        check(status, // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where initially disabled and waiting for update!
                "{",
                "  'current' : {",
                "    'status' : 'ACTIVE',",
                "    'asOf' : '" + toISO(time1) + "',",
                "    'credentialIdExtractor' : 'JWT[1]',",
                "    'loggingLevel' : 'OnlyLimited',",
                "    'limiterMappings' : 8",
                "  },",
                "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
                "}");

        check(updateSucceeded(status, time6), // Example of Rate Limiting Config w/ dynamic 'URL' sourced updates; where update succeeded!
                "{",
                "  'current' : {",
                "    'status' : 'ACTIVE',",
                "    'asOf' : '" + toISO(time6) + "',",
                "    'credentialIdExtractor' : 'JWT[1]',",
                "    'loggingLevel' : 'OnlyLimited',",
                "    'limiterMappings' : 9",
                "  },",
                "  'fromSource' : 'https://github.com/xyz/main/RateLimiters.yaml'",
                "}");
    }

    private RateLimiterStatus createCompletelyDisabled(long asOf) {
        return RateLimiterStatus.builder()
                .current(RateLimiterStatus.Current.builder()
                        .status(RateLimiterStatus.CurrentStatus.DISABLED)
                        .asOf(asOf)
                        .build())
                .build();
    }

    RateLimiterStatus createInitialFileOnlySuccess(long asOf) {
        return RateLimiterStatus.builder()
                .current(RateLimiterStatus.Current.builder()
                        .status(RateLimiterStatus.CurrentStatus.ACTIVE)
                        .asOf(asOf)
                        .credentialIdExtractor("JWT[1]")
                        .loggingLevel("OnlyLimited")
                        .limiterMappings(9)
                        .build())
                .fromSource("Local Config File")
                .build();
    }

    RateLimiterStatus createInitialFileOnlyError(long asOf) {
        return RateLimiterStatus.builder()
                .current(RateLimiterStatus.Current.builder()
                        .status(RateLimiterStatus.CurrentStatus.DISABLED)
                        .asOf(asOf)
                        .error("someError")
                        .build())
                .fromSource("Local Config File")
                .build();
    }

    private RateLimiterStatus createInitialUrlBased(long asOf) {
        return RateLimiterStatus.builder()
                .current(RateLimiterStatus.Current.builder()
                        .status(RateLimiterStatus.CurrentStatus.DISABLED)
                        .asOf(asOf)
                        .build())
                .fromSource("https://github.com/xyz/main/RateLimiters.yaml")
                .build();
    }

    private RateLimiterStatus createInitialFile_AND_UrlBased(long asOf) {
        return RateLimiterStatus.builder()
                .current(RateLimiterStatus.Current.builder()
                        .status(RateLimiterStatus.CurrentStatus.ACTIVE)
                        .asOf(asOf)
                        .credentialIdExtractor("JWT[1]")
                        .loggingLevel("OnlyLimited")
                        .limiterMappings(8)
                        .build())
                .fromSource("https://github.com/xyz/main/RateLimiters.yaml")
                .build();
    }

    private RateLimiterStatus updateSucceeded(RateLimiterStatus status, long asOf) {
        return status.toBuilder()
                .current(RateLimiterStatus.Current.builder()
                        .status(RateLimiterStatus.CurrentStatus.ACTIVE)
                        .asOf(asOf)
                        .credentialIdExtractor("JWT[1]")
                        .loggingLevel("OnlyLimited")
                        .limiterMappings(9)
                        .build())
                .build();
    }

    @Test
    void check_create_AND_update() {
        long time1 = NOW_16_012345; // Times for a time-based sequence

        // Scenario 1
        RateLimiterStatus status = RateLimiterStatus.create(InternalLimiterFactoriesSupplier.NOOP, null, time1, "test");
        check(status,
                "{",
                "  'current' : {",
                "    'status' : 'DISABLED',",
                "    'asOf' : '" + toISO(time1) + "'",
                "  },",
                "  'fromSource' : 'test'",
                "}");
        status = RateLimiterStatus.create(InternalLimiterFactoriesSupplier.NOOP, null, time1, "test");
        check(status,
                "{",
                "  'current' : {",
                "    'status' : 'DISABLED',",
                "    'asOf' : '" + toISO(time1) + "'",
                "  },",
                "  'fromSource' : 'test'",
                "}");

        InternalLimiterFactoriesSupplier mockSupplier = new InternalLimiterFactoriesSupplier() {
            @Override
            public LinkedHashMap<CompoundKey, InternalLimiterFactory> factoryMapFor(RequestInfo info) {
                throw new IllegalStateException("Not Implemented");
            }

            @Override
            public boolean isSupplierNOOP() {
                return false;
            }

            @Override
            public String getCallerCredentialsIdSupplierDescription() {
                return "JWT";
            }

            @Override
            public int getLimiterMappings() {
                return 1;
            }
        };

        // Scenario 2
        status = RateLimiterStatus.create(mockSupplier, null, time1, "test");
        check(status,
                "{",
                "  'current' : {",
                "    'status' : 'ACTIVE',",
                "    'asOf' : '" + toISO(time1) + "',",
                "    'credentialIdExtractor' : 'JWT',",
                "    'loggingLevel' : 'OnlyLimited',",
                "    'limiterMappings' : 1",
                "  },",
                "  'fromSource' : 'test'",
                "}");
    }

    @Test
    void check_noRateLimiting() {
        check(RateLimiterStatus.noRateLimiting(NOW_15_123456),
                "{",
                "  'current' : {",
                "    'status' : 'DISABLED',",
                "    'asOf' : '" + toISO(NOW_15_123456) + "'",
                "  }",
                "}");
    }

    @Test
    void check_toISO8601ZtoSec_Truncation() {
        String now = RateLimiterStatus.toISO8601ZtoSec(System.currentTimeMillis());
        assertThat(now).as(now).hasSize(20);
    }

    private void check(RateLimiterStatus status, String... expected) {
        assertThat(status.hasCurrentSection()).isTrue();
        check(status.toString(), expected);
    }

    private void check(String actualStr, String... expected) {
        StringBuilder sb = new StringBuilder();
        for (String str : expected) {
            if (!sb.isEmpty()) {
                sb.append('\n');
            }
            sb.append(str);
        }
        String expectedStr = sb.toString().replace('\'', '"');
        assertThat(actualStr).isEqualTo(expectedStr);
    }

    private static String toISO(long time) {
        return RateLimiterStatus.toISO8601ZtoSec(time);
    }
}
