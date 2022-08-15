package org.cloudfoundry.identity.uaa.ratelimiting.config;

import lombok.Getter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtilities;

@Getter
public class ErrorSupplierPair {
    private final InternalLimiterFactoriesSupplier supplier;
    private final Exception error;
    private final String errorMsg;

    private ErrorSupplierPair( InternalLimiterFactoriesSupplier supplier, Exception error ) {
        this.supplier = InternalLimiterFactoriesSupplier.deNull( supplier );
        this.error = error;
        this.errorMsg = StringUtilities.toErrorMsg( error );
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

    public RateLimitingFactoriesSupplierWithStatus map( RateLimitingFactoriesSupplierWithStatus existing, String fromSource, boolean updatingEnabled, long asOf ) {
        if ( (existing == null) || !existing.hasStatusCurrentSection() || !updatingEnabled || !supplier.isSupplierNOOP() ) {
            return RateLimitingFactoriesSupplierWithStatus.create( supplier, errorMsg, asOf, fromSource, updatingEnabled );
        }
        return existing.update( errorMsg, asOf, fromSource );
    }
}
