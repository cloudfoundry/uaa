package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class ErrorSupplierPairTest {
    private static final long now15_123456 = Instant.parse("2011-01-15T12:34:56Z").toEpochMilli();
    private static final long now16_012345 = Instant.parse("2011-01-16T01:23:45Z").toEpochMilli();

    @Test
    void map_create() {
        ErrorSupplierPair pair = ErrorSupplierPair.with(new RateLimitingConfigException("testy"));
        RateLimitingFactoriesSupplierWithStatus fsNs = pair.map(null, "map_create", now15_123456);
        assertThat(fsNs.isRateLimitingEnabled()).isTrue();
        assertThat(fsNs.getSupplier().isSupplierNOOP()).isTrue();
        assertThat(fsNs.getStatus()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatusJson()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatus().hasCurrentSection()).isTrue(); // content Tested else where!
        assertThat(fsNs.getStatus().getCurrent().getError()).isEqualTo("testy");
        assertThat(fsNs.getStatus().getCurrent().getAsOf()).isEqualTo(RateLimiterStatus.toISO8601ZtoSec(now15_123456));
        assertThat(fsNs.getStatus().getFromSource()).isEqualTo("map_create");
    }

    @Test
    void map_update() {
        RateLimitingFactoriesSupplierWithStatus existing = new RateLimitingFactoriesSupplierWithStatus(InternalLimiterFactoriesSupplier.NOOP, RateLimiterStatus.noRateLimiting(now15_123456));
        ErrorSupplierPair pair = ErrorSupplierPair.with(InternalLimiterFactoriesSupplier.NOOP);
        RateLimitingFactoriesSupplierWithStatus fsNs = pair.map(existing, "map_update", now16_012345);

        assertThat(fsNs.isRateLimitingEnabled()).isTrue();
        assertThat(fsNs.getSupplier().isSupplierNOOP()).isTrue();
        assertThat(fsNs.getStatus()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatusJson()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatus().hasCurrentSection()).isTrue(); // content Tested else where!
        assertThat(fsNs.getStatus().getCurrent().getError()).isNull();
        assertThat(fsNs.getStatus().getCurrent().getAsOf()).isEqualTo(RateLimiterStatus.toISO8601ZtoSec(now15_123456));
        assertThat(fsNs.getStatus().getFromSource()).isNull(); //TODO Check
    }
}