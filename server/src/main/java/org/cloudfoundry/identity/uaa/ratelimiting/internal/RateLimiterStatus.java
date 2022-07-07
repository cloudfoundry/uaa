package org.cloudfoundry.identity.uaa.ratelimiting.internal;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_NULL)
public class RateLimiterStatus {
    public enum CurrentStatus {DISABLED, PENDING, ACTIVE}

    public enum UpdateStatus {DISABLED, PENDING, FAILED}

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
        public Current( CurrentStatus status, long asOf, String error, String credentialIdExtractor, String loggingLevel, Integer limiterMappings ) {
            this.status = status;
            this.asOf = toISO8601ZtoSec( asOf );
            this.error = error;
            this.credentialIdExtractor = credentialIdExtractor;
            this.loggingLevel = loggingLevel;
            this.limiterMappings = limiterMappings;
        }
    }

    @Getter
    @ToString
    @JsonInclude(Include.NON_NULL)
    public static class Update {
        private final UpdateStatus status;
        private final String asOf; // UTC ISO8601 time to the Second
        private final String error;
        private final Integer checkCountOfStatus;

        private Update( UpdateStatus status, String asOf, String error, Integer checkCountOfStatus ) {
            this.status = status;
            this.asOf = asOf;
            this.error = error;
            this.checkCountOfStatus = checkCountOfStatus;
        }

        @Builder
        public Update( UpdateStatus status, Long asOf, String error, Integer checkCountOfStatus ) {
            this( status, toISO8601ZtoSec( asOf ), error, checkCountOfStatus );
        }

        public boolean isFailed( String withError ) {
            return UpdateStatus.FAILED.equals( status ) && Objects.equals( error, withError );
        }

        @JsonIgnore
        public Update incCheckCountOfStatus() {
            return new Update( status, asOf, error, (checkCountOfStatus == null) ? 1 : (checkCountOfStatus + 1) );
        }
    }

    private final Current current;
    private final Update update; // null on success, as data reflected in current -- UNLESS updating is Disabled!
    private final String fromSource; // null on DISABLED -- local file or http/https url

    @Builder(toBuilder = true)
    public RateLimiterStatus( Current current, Update update, String fromSource ) {
        this.current = current;
        this.update = update;
        this.fromSource = fromSource;
    }

    public Current getCurrent() {
        return current;
    }

    public Update getUpdate() {
        return update;
    }

    public String getFromSource() {
        return fromSource;
    }

    /**
     * Calling this method 'assumes' that an 'update' block exists with the same 'status' and 'error'
     */
    @JsonIgnore
    public RateLimiterStatus incUpdateCountOfStatus() {
        return new RateLimiterStatus( getCurrent(), getUpdate().incCheckCountOfStatus(), getFromSource() );
    }

    public RateLimiterStatus updateFailed( String error, MillisTimeSupplier currentTimeSupplier ) {
        Update update = getUpdate();
        if ( (update != null) && update.isFailed( error ) ) {
            update = update.incCheckCountOfStatus();
        } else {
            update = Update.builder()
                    .status( UpdateStatus.FAILED )
                    .asOf( MillisTimeSupplier.deNull( currentTimeSupplier ).now() )
                    .error( error )
                    .build();
        }
        return new RateLimiterStatus( getCurrent(), update, getFromSource() );
    }

    private transient String generatedJson;

    public String toString() {
        String json = generatedJson;
        if ( json == null ) {
            try {
                json = OM.writerWithDefaultPrettyPrinter().writeValueAsString( this );
            }
            catch ( JsonProcessingException e ) {
                json = "JsonProcessingException (" + e.getMessage() + "): "
                       + "current: " + current
                       + "update: " + update
                       + "fromSource: " + fromSource;
            }
            generatedJson = json;
        }
        return json;
    }

    private static String toISO8601ZtoSec( Long now ) {
        return (now == null) ? null :
               Instant.ofEpochMilli( now ).truncatedTo( ChronoUnit.SECONDS ).toString();
    }

    private static final ObjectMapper OM = new ObjectMapper();

    public static final RateLimiterStatus NO_RATE_LIMITING =
            builder().current( Current.builder().status( CurrentStatus.DISABLED ).asOf( MillisTimeSupplier.SYSTEM.now() ).build() ).build();
}
