package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import java.util.function.Predicate;

import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtilities;

public enum PathMatchType {
    Equals( "start with a slash ('/')", path -> path.startsWith("/") ), //NOSONAR Keep Camelcase, as those are exposed to the yml configuration file
    StartsWith( "start with a slash ('/')", path -> path.startsWith("/") ), //NOSONAR
    Contains( "not be empty", path -> !path.isEmpty() ), //NOSONAR
    Other( "be empty", String::isEmpty ), //NOSONAR
    All( "be empty", String::isEmpty ); //NOSONAR

    private final String pathMust;
    private final Predicate<String> checker;

    PathMatchType(String pathMust, Predicate<String> checker) {
        this.pathMust = pathMust;
        this.checker = checker;
    }

    public String pathUnacceptable(String path) {
        return checker.test(path) ? null : ("must " + pathMust);
    }

    public static String options() {
        return StringUtilities.options(values());
    }
}
