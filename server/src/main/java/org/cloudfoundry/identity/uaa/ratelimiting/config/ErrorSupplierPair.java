package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtilities;

import lombok.Getter;

@Getter
public final class ErrorSupplierPair {
    private final InternalLimiterFactoriesSupplier supplier;
    private final Exception error;
    private final String errorMsg;

    private ErrorSupplierPair(InternalLimiterFactoriesSupplier supplier, Exception error) {
        this.supplier = InternalLimiterFactoriesSupplier.deNull(supplier);
        this.error = error;
        this.errorMsg = StringUtilities.toErrorMsg(error);
    }

    public boolean hasError() {
        return error != null;
    }

    public static ErrorSupplierPair with(InternalLimiterFactoriesSupplier supplier) {
        return new ErrorSupplierPair( supplier, null );
    }

    public static ErrorSupplierPair with(Exception error) {
        return new ErrorSupplierPair( null, error );
    }

    public RateLimitingFactoriesSupplierWithStatus map(RateLimitingFactoriesSupplierWithStatus existing, String fromSource, long asOf) {
        if ((existing == null) || !existing.hasStatusCurrentSection() || !supplier.isSupplierNOOP()) {
            return RateLimitingFactoriesSupplierWithStatus.create(supplier, errorMsg, asOf, fromSource);
        }
        return existing.update();
    }
}
