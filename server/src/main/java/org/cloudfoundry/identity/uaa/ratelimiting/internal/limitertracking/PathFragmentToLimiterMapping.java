package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.Objects;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;

@AllArgsConstructor
@ToString
@Getter
public class PathFragmentToLimiterMapping implements Comparable<PathFragmentToLimiterMapping> {
    private final String pathFragment;
    private final LimiterMapping limiterMapping;

    /**
     * This compareTo is used to order the PathFragmentToLimiterMapping(s) by 1st decreasing pathFragment length, e.g. longer before shorter; then ascending Name
     *
     * @param them not null
     */
    @Override
    public int compareTo( PathFragmentToLimiterMapping them ) {
        int thisLen = this.pathFragment.length();
        int themLen = them.pathFragment.length();
        if ( thisLen != themLen ) {
            // Note: the following trick only works when the subtraction of the ints can not overflow!
            return themLen - thisLen;
        }
        return this.limiterMapping.name().compareTo( them.limiterMapping.name() );
    }

    /**
     * Custom Equals - only check <code>pathFragments</code>
     *
     * @param them to check for equals against <code>this</code>
     * @return true IFF <code>them</code> not null and <code>pathFragments</code> are equal
     */
    public boolean equals( PathFragmentToLimiterMapping them ) {
        return (this == them) || ((them != null)
                                  && this.pathFragment.equals( them.pathFragment ));
    }

    /**
     * Custom Equals - only check <code>pathFragments</code>
     */
    @Override
    public boolean equals( Object them ) {
        return (this == them) || ((them instanceof PathFragmentToLimiterMapping)
                                  && equals( (PathFragmentToLimiterMapping)them ));
    }

    /**
     * Custom hashCode - only process <code>pathFragments</code>
     */
    @Override
    public int hashCode() {
        return Objects.hash( pathFragment );
    }
}
