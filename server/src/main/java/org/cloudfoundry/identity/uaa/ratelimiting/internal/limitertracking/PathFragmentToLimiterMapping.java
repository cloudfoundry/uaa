package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;

@AllArgsConstructor
@ToString
@Getter
@EqualsAndHashCode
public class PathFragmentToLimiterMapping implements Comparable<PathFragmentToLimiterMapping> {
    private final String pathFragment;
    private final LimiterMapping limiterMapping;

    /**
     * This compareTo is used to order the PathFragmentToLimiterMapping(s) by 1st decreasing pathFragment length, e.g. longer before shorter; then ascending Name
     *
     * @param them not null
     */
    @Override
    public int compareTo(PathFragmentToLimiterMapping them) {
        String thisPF = this.pathFragment;
        String themPF = them.pathFragment;
        int thisLen = thisPF.length();
        int themLen = themPF.length();
        if (thisLen != themLen) {
            // Note: the following trick only works when the subtraction of the ints can not overflow!
            return themLen - thisLen;
        }
        return thisPF.compareTo(themPF);
    }
}
