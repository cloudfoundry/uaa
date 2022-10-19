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
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_NULL)
public class RateLimiterStatus {
    public static final RateLimiterStatus NO_RATE_LIMITING = noRateLimiting( MillisTimeSupplier.SYSTEM.now() );

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
            return new Update( status, asOf, error, (checkCountOfStatus == null) ? 2 : (checkCountOfStatus + 1) );
        }
    }

    private final Current current;
    private final Update update; // null on Completely Disabled, as data reflected in current -- w/ updating -> never null!
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

    @JsonIgnore
    public boolean hasCurrentSection() {
        return current != null;
    }

    @JsonIgnore
    public boolean hasUpdateSection() {
        return update != null;
    }

    public RateLimiterStatus updateFailed( String error, long asOf ) {
        Update updateInternal = getUpdate();
        if ( (updateInternal != null) && updateInternal.isFailed( error ) ) {
            updateInternal = updateInternal.incCheckCountOfStatus();
        } else {
            updateInternal = Update.builder().status( UpdateStatus.FAILED ).asOf( asOf ).error( error ).build();
        }
        return new RateLimiterStatus( getCurrent(), updateInternal, getFromSource() );
    }

    public RateLimiterStatus update( String error, long asOf, String fromSource ) {
        Update updateInternal = getUpdate();
        if ( (updateInternal != null) && updateInternal.isFailed( error ) ) {
            updateInternal = updateInternal.incCheckCountOfStatus();
        } else {
            updateInternal = Update.builder().asOf( asOf ).error( error )
                    .status( (error != null) ? UpdateStatus.FAILED : UpdateStatus.PENDING )
                    .build();
        }
        return toBuilder().update( updateInternal ).fromSource( fromSource ).build();
    }

    private String generatedJson;

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

    public static RateLimiterStatus create( InternalLimiterFactoriesSupplier supplier, String error,
                                            long asOf, String fromSource, boolean updatingEnabled ) {
        Current.CurrentBuilder currentBuilder = Current.builder().error( error ).asOf( asOf );

        if ( (supplier == null) || supplier.isSupplierNOOP() ) {
            currentBuilder = currentBuilder.status( updatingEnabled ? CurrentStatus.PENDING : CurrentStatus.DISABLED );
        } else {
            currentBuilder = currentBuilder.status( CurrentStatus.ACTIVE )
                    .loggingLevel( supplier.getLoggingOption().toString() )
                    .credentialIdExtractor( supplier.getCallerCredentialsIdSupplierDescription() );
            int count = supplier.getLimiterMappings();
            if ( count > 0 ) {
                currentBuilder = currentBuilder.limiterMappings( count );
            }
        }
        return builder().current( currentBuilder.build() )
                .update( Update.builder().status( updatingEnabled ? UpdateStatus.PENDING : UpdateStatus.DISABLED ).build() )
                .fromSource( fromSource ).build();
    }

    // public for Testing
    public static String toISO8601ZtoSec( Long now ) {
        return (now == null) ? null :
               Instant.ofEpochMilli( now ).truncatedTo( ChronoUnit.SECONDS ).toString();
    }

    // public for Testing
    public static RateLimiterStatus noRateLimiting( long now ) {
        return builder().current( Current.builder().status( CurrentStatus.DISABLED ).asOf( now ).build() ).build();
    }

    private static final ObjectMapper OM = new ObjectMapper();
}
