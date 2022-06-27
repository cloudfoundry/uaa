package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;

public class ExpirationBuckets implements CompoundKeyExpirationAdder,
                                          Runnable {
    private final MillisTimeSupplier currentTimeSupplier;
    private final CompoundKeyPurger compoundKeyPurger;
    private final int wrapAroundMask;
    private final long buckets; // need long version for efficient bounds checking
    private final List<CompoundKey>[] expirationsBucketRing;
    private ExpirationBucketMapping ebm;
    private volatile boolean wereDying = false;

    public ExpirationBuckets( MillisTimeSupplier currentTimeSupplier, CompoundKeyPurger compoundKeyPurger,
                              int minimumBuckets ) {
        this.currentTimeSupplier = currentTimeSupplier;
        this.compoundKeyPurger = compoundKeyPurger;
        int buckets = powerOf2atLeast( minimumBuckets + 2 ); // need extra two (seconds)
        this.buckets = buckets; // long version for efficient bounds checking
        wrapAroundMask = buckets - 1;
        //noinspection unchecked
        expirationsBucketRing = new List[buckets];
        for ( int i = 0; i < expirationsBucketRing.length; i++ ) {
            expirationsBucketRing[i] = Collections.synchronizedList( new LinkedList<>() ); // Cheap adding!
        }
        // provide ebm with purging 'tail' being two seconds behind available adding offsets
        ebm = new ExpirationBucketMapping( 0,
                                           currentSecondNow() - 2,
                                           wrapAroundMask );
    }

    @Override
    public void addCompoundKeyExpiration( CompoundKey compoundKey, long expirationSecond ) {
        List<CompoundKey> bucket = getBucket( expirationSecond );
        bucket.add( compoundKey );
    }

    public void die() {
        wereDying = true;
    }

    // public for testing
    public void processExpirations() {
        long secondToPurge = currentSecondNow() - 2; // purge two seconds behind possible adds!
        purge( getBucket( secondToPurge ), compoundKeyPurger, secondToPurge );
        updateBucketBase( secondToPurge );
    }

    @SuppressWarnings({"BusyWait"})
    @Override
    public void run() {
        while ( !wereDying ) {
            try {
                Thread.sleep( 300 ); // check at least 3 times per second
                processExpirations();
            }
            catch ( InterruptedException e ) {
                // As it is a Daemon, ignore InterruptedException
            }
            catch ( RuntimeException e ) {
                e.printStackTrace(); // Log everything else
            }
        }
    }

    // Following 4 methods package friendly testing

    int getWrapAroundMask() {
        return wrapAroundMask;
    }

    long currentSecondNow() {
        return currentTimeSupplier.now() / 1000L; // Drop msecs
    }

    synchronized ExpirationBucketMapping getExpirationBucketMapping() {
        return ebm;
    }

    private synchronized void updateBucketBase( long secondJustPurged ) {
        if ( ebm.currentRingBucketBaseSecond < secondJustPurged ) { // Can move base forward
            ebm = ebm.increment();
        }
    }

    synchronized List<CompoundKey> getBucket( long secondOfInterest ) {
        long secondsOffset = secondOfInterest - ebm.currentRingBucketBaseSecond;
        if ( (secondsOffset < 0) || (buckets <= secondsOffset) ) {
            throw new BucketRingBoundsException( ebm, buckets, secondOfInterest );
        }
        int offset = constrainBucketOffset( ebm.currentRingBucketBaseOffset + (int)secondsOffset );
        return expirationsBucketRing[offset];
    }

    private int constrainBucketOffset( int offset ) {
        // Binary And-ing causes wrapping (only works on "Powers Of TWO")!
        return (offset & wrapAroundMask);
    }

    private static int powerOf2atLeast( int minimum ) {
        int powerOf2 = 16; // minimum buckets
        while ( powerOf2 < minimum ) {
            powerOf2 += powerOf2;
            if ( powerOf2 < 0 ) { // wrapped to negative?
                throw new IllegalStateException( "Unable to generate an integer power of two as large as: " + minimum );
            }
        }
        return powerOf2;
    }

    public static class BucketRingBoundsException extends IllegalStateException {
        private BucketRingBoundsException( ExpirationBucketMapping ebm, long buckets, long secondOfInterest ) {
            super( "Second requested outside of current BucketRing window: " +
                   ebm.currentRingBucketBaseSecond +
                   " <= " + secondOfInterest + " < " +
                   (ebm.currentRingBucketBaseSecond + buckets) );
        }
    }

    @RequiredArgsConstructor
    @Getter
    @ToString
    static class ExpirationBucketMapping {
        private final int currentRingBucketBaseOffset;
        private final long currentRingBucketBaseSecond;
        private final int wrapAroundMask;

        ExpirationBucketMapping increment() {
            return new ExpirationBucketMapping( wrapAroundMask & (currentRingBucketBaseOffset + 1),
                                                currentRingBucketBaseSecond + 1,
                                                wrapAroundMask );
        }
    }

    public void purge( List<CompoundKey> keys, CompoundKeyPurger compoundKeyPurger, long secondToPurge ) {
        for ( CompoundKey compoundKey : keys ) {
            compoundKeyPurger.removeCompoundKey( compoundKey, secondToPurge );
        }
        keys.clear();
    }
}
