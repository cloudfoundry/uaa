package org.cloudfoundry.identity.uaa.ratelimiting.internal;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_NULL)
public class RateLimiterStatus {
    public static final RateLimiterStatus NO_RATE_LIMITING = noRateLimiting(TimeUnit.NANOSECONDS.toMillis(NanoTimeSupplier.SYSTEM.now()));

    public enum CurrentStatus {DISABLED, PENDING, ACTIVE
    }

    @Getter
    @ToString
    @JsonInclude(Include.NON_NULL)
    public static class Current {
        private final CurrentStatus status;
        private final String asOf; // UTC ISO8601 time to the Second
        private final String error;
        private final String credentialIdExtractor; // null on start state
        private final String loggingLevel; // null on start state
        private final Integer limiterMappings; // null on start state

        @Builder
        public Current(CurrentStatus status, long asOf, String error, String credentialIdExtractor, String loggingLevel, Integer limiterMappings) {
            this.status = status;
            this.asOf = toISO8601ZtoSec(asOf);
            this.error = error;
            this.credentialIdExtractor = credentialIdExtractor;
            this.loggingLevel = loggingLevel;
            this.limiterMappings = limiterMappings;
        }
    }

    private final Current current;
    private final String fromSource; // null on DISABLED -- local file or http/https url

    @Builder(toBuilder = true)
    public RateLimiterStatus(Current current, String fromSource) {
        this.current = current;
        this.fromSource = fromSource;
    }

    public Current getCurrent() {
        return current;
    }

    public String getFromSource() {
        return fromSource;
    }

    @JsonIgnore
    public boolean hasCurrentSection() {
        return current != null;
    }

    private String generatedJson;

    public String toString() {
        String json = generatedJson;
        if (json == null) {
            try {
                json = OM.writerWithDefaultPrettyPrinter().writeValueAsString(this);
            }
            catch (JsonProcessingException e) {
                json = "JsonProcessingException (" + e.getMessage() + "): "
                        + "current: " + current
                        + "fromSource: " + fromSource;
            }
            generatedJson = json;
        }
        return json;
    }

    public static RateLimiterStatus create(InternalLimiterFactoriesSupplier supplier, String error,
            long asOf, String fromSource) {
        Current.CurrentBuilder currentBuilder = Current.builder().error(error).asOf(asOf);

        if ((supplier == null) || supplier.isSupplierNOOP()) {
            currentBuilder = currentBuilder.status(CurrentStatus.DISABLED);
        } else {
            currentBuilder = currentBuilder.status(CurrentStatus.ACTIVE)
                    .loggingLevel(supplier.getLoggingOption().toString())
                    .credentialIdExtractor(supplier.getCallerCredentialsIdSupplierDescription());
            int count = supplier.getLimiterMappings();
            if (count > 0) {
                currentBuilder = currentBuilder.limiterMappings(count);
            }
        }
        return builder().current(currentBuilder.build())
                .fromSource(fromSource).build();
    }

    // public for Testing
    public static String toISO8601ZtoSec(Long now) {
        return now == null ? null :
                Instant.ofEpochMilli(now).truncatedTo(ChronoUnit.SECONDS).toString();
    }

    // public for Testing
    public static RateLimiterStatus noRateLimiting(long now) {
        return builder().current(Current.builder().status(CurrentStatus.DISABLED).asOf(now).build()).build();
    }

    private static final ObjectMapper OM = new ObjectMapper();
}
