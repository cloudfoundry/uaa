package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.Objects;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.TypeProperties;

@AllArgsConstructor
@ToString
@Getter
public class PathFragmentToTypeProperties implements Comparable<PathFragmentToTypeProperties> {
    private final String pathFragment;
    private final TypeProperties properties;

    /**
     * This compareTo is used to order the PathFragmentToTypeProperties by decreasing pathFragment length, e.g. longer before shorter
     *
     * @param them not null
     */
    @Override
    public int compareTo( PathFragmentToTypeProperties them ) {
        int thisLen = this.pathFragment.length();
        int themLen = them.pathFragment.length();
        // Note: the following trick only works when the subtraction of the ints can not overflow!
        return themLen - thisLen;
    }

    /**
     * Custom Equals - only check <code>pathFragments</code>
     *
     * @param them to check for equals against <code>this</code>
     * @return true IFF <code>them</code> not null and <code>pathFragments</code> are equal
     */
    public boolean equals( PathFragmentToTypeProperties them ) {
        return (this == them) || ((them != null)
                                  && this.pathFragment.equals( them.pathFragment ));
    }

    /**
     * Custom Equals - only check <code>pathFragments</code>
     */
    @Override
    public boolean equals( Object them ) {
        return (this == them) || ((them instanceof PathFragmentToTypeProperties)
                                  && equals( (PathFragmentToTypeProperties)them ));
    }

    /**
     * Custom hashCode - only process <code>pathFragments</code>
     */
    @Override
    public int hashCode() {
        return Objects.hash( pathFragment );
    }
}
