package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitingFactoriesSupplierWithStatusTest {
    private static final long now15_123456 = Instant.parse("2011-01-15T12:34:56Z").toEpochMilli();
    private static final long now16_012345 = Instant.parse("2011-01-16T01:23:45Z").toEpochMilli();
    private static final long now16_013000 = Instant.parse("2011-01-16T01:30:00Z").toEpochMilli();

    @Test
    void general() {
        RateLimitingFactoriesSupplierWithStatus fsNs = RateLimitingFactoriesSupplierWithStatus.builder().build();
        assertThat(fsNs.isRateLimitingEnabled()).isFalse();
        assertThat(fsNs.getStatus()).isNull();
        assertThat(fsNs.getStatusJson()).isNull();
        fsNs = fsNs.toBuilder().status(RateLimiterStatus.NO_RATE_LIMITING).supplier(InternalLimiterFactoriesSupplier.NOOP).build();
        assertThat(fsNs.isRateLimitingEnabled()).isTrue();
        assertThat(fsNs.getSupplier()).isEqualTo(InternalLimiterFactoriesSupplier.NOOP);
        assertThat(fsNs.getStatus()).isEqualTo(RateLimiterStatus.NO_RATE_LIMITING);
        assertThat(fsNs.getStatusJson()).isNotNull(); // Tested else where!
    }

    @Test
    void create_updateError_update() {
        RateLimitingFactoriesSupplierWithStatus fsNs = RateLimitingFactoriesSupplierWithStatus
                .create(null, null, now15_123456, "test");
        assertThat(fsNs.isRateLimitingEnabled()).isFalse();
        assertThat(fsNs.getStatus()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatusJson()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatus().hasCurrentSection()).isTrue(); // content Tested else where!
        assertThat(fsNs.getStatus().getCurrent().getError()).isNull();
        assertThat(fsNs.getStatus().getFromSource()).isEqualTo("test");

        fsNs = fsNs.updateError(new RateLimitingConfigException("testy"));
        assertThat(fsNs.getStatus()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatusJson()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatus().hasCurrentSection()).isTrue(); // content Tested else where!
        assertThat(fsNs.getStatus().getCurrent().getError()).isNull();
        assertThat(fsNs.getStatus().getFromSource()).isEqualTo("test");

        fsNs = fsNs.update();
        assertThat(fsNs.getStatus()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatusJson()).isNotNull(); // Tested else where!
        assertThat(fsNs.getStatus().hasCurrentSection()).isTrue(); // content Tested else where!
        assertThat(fsNs.getStatus().getCurrent().getError()).isNull();
        assertThat(fsNs.getStatus().getFromSource()).isEqualTo("test");
    }
}