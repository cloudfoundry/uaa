package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

public class IntUtils {
    public static Integer parseNoException( String source, Integer defaultOnEmpty ) {
        try {
            return parse( source, defaultOnEmpty );
        }
        catch ( NumberFormatException e ) {
            return null;
        }
    }

    public static Integer parse( String source, Integer defaultOnEmpty ) {
        source = StringUtils.normalizeToEmpty( source );
        return source.isEmpty() ? defaultOnEmpty : Integer.valueOf( Integer.parseInt( source ) );
    }

    public static <T> Integer minimumFrom( List<T> items, Function<T, Integer> mapper ) {
        if ( (items != null) && (mapper != null) ) {
            Optional<Integer> min = items.stream().filter( Objects::nonNull ).map( mapper ).filter( Objects::nonNull )
                    .min( Integer::compare );
            return min.orElse( null );
        }
        return null; // No values
    }
}
