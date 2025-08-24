package org.cloudfoundry.identity.uaa.ratelimiting.internal.common;

import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LimiterImplTest {

    @Test
    void shouldLimit() {
        InternalLimiter iLimiter1 = iLimiterNew("1st", 0);
        InternalLimiter iLimiter2 = iLimiterNew("2nd", 2);
        InternalLimiter iLimiter3 = iLimiterNew("3rd", 1);

        check("A", List.of(iLimiter1), true,
                "Limiter: --LIMIT-- ",
                "--LIMIT-- |1st|");

        check("B", List.of(iLimiter1, iLimiter2), true,
                "Limiter: --LIMIT-- ",
                "--LIMIT-- |1st|",
                "noCheck   |2nd|");

        check("C", List.of(iLimiter1, iLimiter3), true,
                "Limiter: --LIMIT-- ",
                "--LIMIT-- |1st|",
                "noCheck   |3rd|");

        check("D", List.of(iLimiter2, iLimiter3), false,
                "Limiter: ",
                "forward   |2nd| (1)",
                "forward   |3rd| (0)");

        check("E", List.of(iLimiter2, iLimiter3), true,
                "Limiter: --LIMIT-- ",
                "forward   |2nd|",
                "--LIMIT-- |3rd|");
    }

    private InternalLimiter iLimiterNew(String compoundKeyMiddle, int limit) {
        CompoundKey compoundKey = CompoundKey.from("", compoundKeyMiddle, "");
        return new InternalLimiter(compoundKey, limit, Instant.now());
    }

    private void check(String callID, List<InternalLimiter> iLimiters, boolean shouldLimitExpected, String... toStringLines) {
        LimiterImpl limiter = LimiterImpl.from(iLimiters, LoggingOption.AllCallsWithDetails);
        assertThat(limiter.shouldLimit()).as(callID).isEqualTo(shouldLimitExpected);
        String expected = String.join("\n", toStringLines);
        assertThat(limiter).as(callID).hasToString(expected);
    }
}
