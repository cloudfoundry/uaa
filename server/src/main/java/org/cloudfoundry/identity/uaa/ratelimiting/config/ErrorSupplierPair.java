package org.cloudfoundry.identity.uaa.ratelimiting.config;

import lombok.Getter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

import static org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus.*;

@Getter
public class ErrorSupplierPair {
    private final InternalLimiterFactoriesSupplier supplier;
    private final Exception error;
    private final String errorMsg;

    private ErrorSupplierPair( InternalLimiterFactoriesSupplier supplier, Exception error ) {
        this.supplier = InternalLimiterFactoriesSupplier.deNull( supplier );
        this.error = error;
        this.errorMsg = StringUtils.toErrorMsg( error );
    }

    public boolean isSupplierNOOP() {
        return (supplier == InternalLimiterFactoriesSupplier.NOOP);
    }

    public boolean hasError() {
        return (error != null);
    }

    public static ErrorSupplierPair with( InternalLimiterFactoriesSupplier supplier ) {
        return new ErrorSupplierPair( supplier, null );
    }

    public static ErrorSupplierPair with( Exception error ) {
        return new ErrorSupplierPair( null, error );
    }

    public RateLimitingFactoriesSupplierWithStatus map( RateLimitingFactoriesSupplierWithStatus current, String fromSource, boolean updatingEnabled, long asOf ) {
        if ( !isSupplierNOOP() || !updatingEnabled || (current == null) || (current.getStatus() == null) || (current.getStatus().getCurrent() == null) ) {
            return populateCurrent( asOf, fromSource, updatingEnabled );
        }
        return populateUpdate( current, asOf, fromSource );
    }

    private RateLimitingFactoriesSupplierWithStatus populateCurrent( long asOf, String fromSource, boolean updatingEnabled ) {
        RateLimiterStatus.Current current = buildCurrent( asOf, updatingEnabled );
        RateLimiterStatus.Update update = RateLimiterStatus.Update.builder()
                .status( updatingEnabled ? RateLimiterStatus.UpdateStatus.PENDING : RateLimiterStatus.UpdateStatus.DISABLED )
                .build();

        return RateLimitingFactoriesSupplierWithStatus.builder()
                .supplier( supplier )
                .status( RateLimiterStatus.builder()
                                 .current( current )
                                 .update( update )
                                 .fromSource( fromSource )
                                 .build() ).build();
    }

    private RateLimitingFactoriesSupplierWithStatus populateUpdate( RateLimitingFactoriesSupplierWithStatus current,
                                                                    long asOf, String fromSource ) {
        RateLimiterStatus status = current.getStatus();

        Update update = status.getUpdate();
        if ( update.isFailed( errorMsg ) ) {
            update = update.incCheckCountOfStatus();
        } else {
            update = Update.builder().asOf( asOf ).error( errorMsg )
                    .status( hasError() ? UpdateStatus.FAILED : UpdateStatus.PENDING )
                    .build();
        }

        return current.toBuilder()
                .status( status.toBuilder().update( update ).fromSource( fromSource )
                                 .build() ).build();
    }

    private RateLimiterStatus.Current buildCurrent( long asOf, boolean updatingEnabled ) {
        Current.CurrentBuilder builder = Current.builder().asOf( asOf ).error( errorMsg );

        if ( isSupplierNOOP() ) {
            return builder.status( updatingEnabled ? CurrentStatus.PENDING : CurrentStatus.DISABLED ).build();
        }
        return builder.status( CurrentStatus.ACTIVE )
                .loggingLevel( supplier.getLoggingOption().toString() )
                .credentialIdExtractor( supplier.getCallerCredentialsIdSupplierDescription() )
                .limiterMappings( extractLimiterMappingsCount() ).build();
    }

    private Integer extractLimiterMappingsCount() {
        int count = supplier.getLimiterMappings();
        return (count == 0) ? null : count;
    }
}
