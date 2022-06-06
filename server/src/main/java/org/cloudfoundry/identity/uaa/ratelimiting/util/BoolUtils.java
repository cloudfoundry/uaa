package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.List;
import java.util.function.Predicate;

public class BoolUtils {
    public static <T> Boolean anyTrue( List<T> items, Predicate<T> mapper ) {
        if ( (items != null) && (mapper != null) ) {
            boolean anyItems = false;
            for ( T item : items ) {
                if ( item != null ) {
                    if ( mapper.test( item ) ) {
                        return true;
                    }
                    anyItems = true;
                }
            }
            if ( anyItems ) {
                return false;
            }
        }
        return null; // None Found / findable
    }
}
