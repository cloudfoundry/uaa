package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import java.util.function.Predicate;

import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

public enum PathMatchType {
    Equals( "start with a slash ('/')", path -> path.startsWith( "/" ) ),
    StartsWith( "start with a slash ('/')", path -> path.startsWith( "/" ) ),
    Contains( "not be empty", path -> !path.isEmpty() ),
    Other( "be empty", String::isEmpty ),
    All( "be empty", String::isEmpty );

    private final String pathMust;
    private final Predicate<String> checker;

    PathMatchType( String pathMust, Predicate<String> checker ) {
        this.pathMust = pathMust;
        this.checker = checker;
    }

    public String pathUnacceptable( String path ) {
        return checker.test( path ) ? null : ("must " + pathMust);
    }

    public static String options() {
        return StringUtils.options( values() );
    }
}
