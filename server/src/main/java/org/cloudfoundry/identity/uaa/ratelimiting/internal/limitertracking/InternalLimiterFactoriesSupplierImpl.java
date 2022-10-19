package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import lombok.NonNull;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.PathMatchType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.PathSelector;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CallerIdSupplierByTypeFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.RequestInfo;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.CallerIdSupplierByTypeFactoryFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactory;

public class InternalLimiterFactoriesSupplierImpl implements InternalLimiterFactoriesSupplier {
    static final String TO_STRING_INDENT = "   ";

    private final Map<String, LimiterMapping> pathEqualsToProperties = new LinkedHashMap<>();
    private final PathFragmentToTypePropertiesMapper pathStartsWithProperties;
    private final PathFragmentToTypePropertiesMapper pathContainsProperties;
    private final LimiterMapping pathOtherProperties;
    private final LimiterMapping allProperties;
    private final int limiterMappings;
    private final LoggingOption loggingOption;

    // public for testing
    public final CallerIdSupplierByTypeFactory callerIdSupplierByTypeFactory;

    @Override
    @NonNull
    public LoggingOption getLoggingOption() {
        return loggingOption;
    }

    @Override
    public String getCallerCredentialsIdSupplierDescription() {
        return callerIdSupplierByTypeFactory.getCallerCredentialsIdSupplierDescription();
    }

    @Override
    public int getLimiterMappings() {
        return limiterMappings;
    }

    @Override
    public LinkedHashMap<CompoundKey, InternalLimiterFactory> factoryMapFor( RequestInfo info ) {
        return internalFactoryMapFor( callerIdSupplierByTypeFactory.from( info ), info.getServletPath() );
    }

    public int typePropertiesPathOptionsCount() {
        return cnt( pathEqualsToProperties ) + cnt( pathStartsWithProperties ) + cnt( pathContainsProperties ) + cnt( pathOtherProperties ) + cnt( allProperties );
    }

    // package friendly for testing
    LinkedHashMap<CompoundKey, InternalLimiterFactory> internalFactoryMapFor( CallerIdSupplierByType callerIdSupplierByType, String servletPath ) {
        return mapFrom( callerIdSupplierByType,
                        getPathBasedProperties( servletPath ), allProperties );
    }

    // package friendly for testing
    LimiterMapping getPathBasedProperties( String servletPath ) { // Method shows how the search algorithm works!
        LimiterMapping pathProperties;
        if ( (servletPath == null) || servletPath.isEmpty() ) {
            pathProperties = pathOtherProperties;
        } else {
            if ( null == (pathProperties = pathEqualsToProperties.get( servletPath )) ) { // . . . . . 1st - Direct look up for Equals
                if ( null == (pathProperties = pathStartsWithProperties.get( servletPath )) ) { // . . 2nd - Longest PathFragment that StartsWith
                    if ( null == (pathProperties = pathContainsProperties.get( servletPath )) ) { // . 3rd - Longest PathFragment that Contains
                        pathProperties = pathOtherProperties; // . . . . . . . . . . . . . . . . . . . 4th - Other
                    }
                }
            }
        }
        return pathProperties;
    }

    /**
     * Code that creates the compoundKey to factories in a consistent (and hopefully best) order (least likely to have lock contention to most likely).
     */
    // package friendly for testing
    static LinkedHashMap<CompoundKey, InternalLimiterFactory> mapFrom( CallerIdSupplierByType callerIdSupplierByType,
                                                                       LimiterMapping propsPath, LimiterMapping propsAll ) {
        LinkedHashMap<CompoundKey, InternalLimiterFactory> map = new LinkedHashMap<>();
        WindowType.NON_GLOBAL.addBestTo( map, propsPath, callerIdSupplierByType ); // non Globals first
        WindowType.NON_GLOBAL.addBestTo( map, propsAll, callerIdSupplierByType );
        WindowType.GLOBAL.addTo( map, propsPath, callerIdSupplierByType ); // then Globals
        WindowType.GLOBAL.addTo( map, propsAll, callerIdSupplierByType );
        return map;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder().append( "InternalLimiterFactoriesSupplier:" );
        appendTo( sb, PathMatchType.Equals, pathEqualsToProperties );
        appendTo( sb, PathMatchType.StartsWith, pathStartsWithProperties );
        appendTo( sb, PathMatchType.Contains, pathContainsProperties );
        appendTo( sb, PathMatchType.Other, pathOtherProperties );
        appendTo( sb, PathMatchType.All, allProperties );
        return sb.append( '\n' ).toString();
    }

    /**
     * Constructor
     *
     * @param credentialIdExtractor null defaults to Client (caller's) IP only
     * @param limiterMappings       if empty it throws an error
     * @throws RateLimitingConfigException if any of the TypeProperties are bad or collide with another or basic filtering is not included!
     */
    public InternalLimiterFactoriesSupplierImpl( AuthorizationCredentialIdExtractor credentialIdExtractor,
                                                 LoggingOption loggingOption, Collection<LimiterMapping> limiterMappings ) {
        callerIdSupplierByTypeFactory = CallerIdSupplierByTypeFactoryFactory.from( credentialIdExtractor );
        this.loggingOption = LoggingOption.deNull( loggingOption );
        int countLimiterMappings = 0;

        List<PathFragmentToTypeProperties> ptfStartsWiths = new ArrayList<>();
        List<PathFragmentToTypeProperties> ptfContains = new ArrayList<>();
        LimiterMapping pathOtherProperties = null;
        LimiterMapping allProperties = null;
        for ( LimiterMapping limiterMapping : limiterMappings ) {
            if ( limiterMapping != null ) {
                countLimiterMappings++;
                List<PathSelector> selectors = limiterMapping.pathSelectors();
                for ( PathSelector selector : selectors ) {
                    PathMatchType pmType = selector.getType();

                    switch ( pmType ) {
                        case Equals:
                            pathEqualsToProperties.put( selector.getPath(), limiterMapping );
                            break;
                        case StartsWith:
                            ptfStartsWiths.add( new PathFragmentToTypeProperties( selector.getPath(), limiterMapping ) );
                            break;
                        case Contains:
                            ptfContains.add( new PathFragmentToTypeProperties( selector.getPath(), limiterMapping ) );
                            break;
                        case Other:
                            pathOtherProperties = limiterMapping;
                            break;
                        case All:
                            allProperties = limiterMapping;
                            break;
                        default:
                            throw new RateLimitingConfigException( "Unexpected PathMatchType '" + pmType + "' on: " + limiterMapping.name() );
                    }
                }
            }
        }
        pathStartsWithProperties = new PathFragmentToTypePropertiesMapper( String::startsWith, ptfStartsWiths );
        pathContainsProperties = new PathFragmentToTypePropertiesMapper( String::contains, ptfContains );
        this.pathOtherProperties = pathOtherProperties;
        this.allProperties = allProperties;
        this.limiterMappings = countLimiterMappings;
    }

    @SuppressWarnings("SameParameterValue")
    private static void appendTo( StringBuilder sb, PathMatchType type, Map<String, LimiterMapping> pathProperties ) {
        appendPathMatchType( sb, type, !pathProperties.isEmpty() );
        for ( String path : pathProperties.keySet() ) {
            appendPropertiesWithPath( sb, path, pathProperties.get( path ) );
        }
    }

    private static void appendTo( StringBuilder sb, PathMatchType type, PathFragmentToTypePropertiesMapper mapper ) {
        appendPathMatchType( sb, type, !mapper.isEmpty() );
        mapper.stream().forEach( t -> appendPropertiesWithPath( sb, t.getPathFragment(), t.getProperties() ) );
    }

    @SuppressWarnings("SameParameterValue")
    private static void appendTo( StringBuilder sb, PathMatchType type, LimiterMapping properties ) {
        if ( properties != null ) {
            appendPathMatchType( sb, type, true );
            appendPropertiesWithPath( sb, null, properties );
        }
    }

    private static void appendPathMatchType( StringBuilder sb, PathMatchType type, boolean atLeastOne ) {
        if ( atLeastOne ) {
            sb.append( '\n' ).append( TO_STRING_INDENT ).append( type ).append( ':' );
        }
    }

    private static void appendPropertiesWithPath( StringBuilder sb, String path, LimiterMapping properties ) {
        sb.append( '\n' ).append( TO_STRING_INDENT ).append( TO_STRING_INDENT );
        if ( path != null ) {
            sb.append( path ).append( " -> " );
        }
        sb.append( properties.name() ).append( ":" );
        boolean multiple = properties.limitsCount() > 1;
        for ( WindowType type : WindowType.ALL_WINDOW_TYPES ) {
            appendLimits( sb, multiple, type.windowType(), type.extractRequestsPerWindowFrom( properties ) );
        }
    }

    private static void appendLimits( StringBuilder sb, boolean multiple, String limitsName, RequestsPerWindowSecs limits ) {
        if ( limits != null ) {
            if ( multiple ) {
                sb.append( '\n' ).append( TO_STRING_INDENT ).append( TO_STRING_INDENT ).append( TO_STRING_INDENT );
            }
            sb.append( limitsName ).append( " @ " ).append( limits );
        }
    }

    private static int cnt( Object o ) {
        return (o == null) ? 0 : 1;
    }

    private static int cnt( PathFragmentToTypePropertiesMapper mapper ) {
        return mapper.count();
    }

    private static int cnt( Map<?, ?> map ) {
        return map.size();
    }
}
