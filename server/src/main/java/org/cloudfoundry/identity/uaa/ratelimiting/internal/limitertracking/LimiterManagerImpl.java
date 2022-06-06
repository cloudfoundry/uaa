package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import lombok.NonNull;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.Limiter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LimiterManager;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiter;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterFactorySupplierUpdatable;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;

public class LimiterManagerImpl implements LimiterManager,
                                           LimiterFactorySupplierUpdatable {
    public static class Singleton {
        private static final LimiterManagerImpl[] INDIRECT_INSTANCE_REF = new LimiterManagerImpl[1];

        public static LimiterManagerImpl getInstance() { //
            synchronized ( INDIRECT_INSTANCE_REF ) {
                LimiterManagerImpl manager = INDIRECT_INSTANCE_REF[0];
                if ( manager == null ) { // create an Instance with Rate Limiting disabled
                    manager = new LimiterManagerImpl( null );
                    INDIRECT_INSTANCE_REF[0] = manager;
                }
                return manager;
            }
        }
    }

    private final LimiterByCompoundKey limiterByCompoundKey; // dynamically managed!
    private final ExpirationBuckets expirationBuckets;
    private volatile InternalLimiterFactoriesSupplier limiterFactorySupplier = InternalLimiterFactoriesSupplier.NOOP; // !null
    private Thread backgroundThread;

    // package friendly for testing
    InternalLimiterFactoriesSupplier getFactorySupplier() {
        return limiterFactorySupplier;
    }

    @Override
    public Limiter getLimiter( RequestInfo info ) {
        // Due to the volatile nature of limiterFactorySupplier - all work should occur from a single reference to it!
        InternalLimiterFactoriesSupplier supplier = limiterFactorySupplier;
        return createLimiter( generateLimiterList( info, supplier ), supplier.getLoggingOption() );
    }

    /**
     * Generate a list of Internal Limiters (1-n).
     * <p>
     * Note: the list of <code>InternalLimiter</code> must be appropriately ordered, which means:<ul>
     * <li>Consistent - every pair of <code>InternalLimiter</code> (based on the combination of name and limiting type) should always be in the same order</li>
     * <li>Frequency (of list membership) try for least to most - <code>globals</code> (not using any caller ID) should be later in the list</li>
     * </ul>
     * <p>
     * Note-2: Consistent ordering ensures no Dead Locks when creating the exclusive access for each entry in order.
     * <p>
     * Note-3: Frequency order is immaterial, if no limiting is indicated, as every <code>InternalLimiter</code> must be checked.
     * However, if any <code>InternalLimiter</code>, before the last one, indicates limiting, then subsequent <code>InternalLimiter</code>(s)
     * are not involved, and they are not seized for exclusive access.
     */
    // package protected for testing
    List<InternalLimiter> generateLimiterList( RequestInfo info, InternalLimiterFactoriesSupplier supplier ) {
        Map<CompoundKey, InternalLimiterFactory> factoryMap = supplier.factoryMapFor( info );
        if ( (factoryMap == null) || factoryMap.isEmpty() ) { // null is the initial default from the NOOP version
            return null;
        }
        List<InternalLimiter> limiters = new ArrayList<>( factoryMap.size() );
        for ( CompoundKey compoundKey : factoryMap.keySet() ) { // Priority/Lock order!
            limiters.add( limiterByCompoundKey.get( compoundKey, factoryMap.get( compoundKey ), expirationBuckets ) );
        }
        return limiters;
    }

    /**
     * Create and return a Limiter - either a <code>Limiter.FORWARD_REQUEST</code> which indicates limiting is effectively disabled OR a <code>LimiterImpl</code>.
     * <p>
     * Note: If <code>LimiterImpl</code> indicates limiting, then none of the InternalLimiter(s) should have their <code>requestsRemaining</code> reduced
     * Note: If <code>LimiterImpl</code> indicates NOT limiting, then ALL the InternalLimiter(s) should have their <code>requestsRemaining</code> reduced
     *
     * @param limiters      null or a non empty list of <code>InternalLimiter</code>(s)
     * @param loggingOption a non-Null enum that indicates the logging approach
     * @return either <code>Limiter.FORWARD_REQUEST</code> or a <code>LimiterImpl</code>
     */
    // package protected for testing
    Limiter createLimiter( List<InternalLimiter> limiters, @NonNull LoggingOption loggingOption ) { // null or not empty
        return limiters == null ? Limiter.FORWARD_REQUEST : LimiterImpl.from( limiters, loggingOption );
    }

    @Override
    public void update( InternalLimiterFactoriesSupplier factoryByTypeSupplier ) {
        if ( factoryByTypeSupplier != null ) {
            this.limiterFactorySupplier = factoryByTypeSupplier;
        }
    }

    @Override
    public synchronized void startBackgroundProcessing() {
        if ( backgroundThread == null ) {
            backgroundThread = new Thread( expirationBuckets );
            backgroundThread.setName( "LimiterExpirationProcess" );
            backgroundThread.setDaemon( true );
            backgroundThread.start();
        }
    }

    @Override
    public synchronized void shutdownBackgroundProcessing() {
        expirationBuckets.die();
        if ( backgroundThread != null ) {
            backgroundThread.interrupt();
            backgroundThread = null;
        }
    }

    // package protected for testing
    LimiterManagerImpl( MillisTimeSupplier currentTimeSupplier ) {
        currentTimeSupplier = MillisTimeSupplier.deNull( currentTimeSupplier );
        limiterByCompoundKey = new LimiterByCompoundKey( currentTimeSupplier );
        expirationBuckets = new ExpirationBuckets( currentTimeSupplier, limiterByCompoundKey,
                                                   RequestsPerWindowSecs.MAX_WINDOW_SECONDS );
    }

    // package protected for testing
    void processExpirations() {
        expirationBuckets.processExpirations();
    }
}
