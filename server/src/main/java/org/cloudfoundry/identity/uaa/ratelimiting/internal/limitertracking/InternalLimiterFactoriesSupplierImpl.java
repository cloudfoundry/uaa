package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import lombok.NonNull;
import org.cloudfoundry.identity.uaa.ratelimiting.core.CompoundKey;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.PathMatchType;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.PathSelector;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.RequestsPerWindowSecs;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.TypeProperties;
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

    private final Map<String, TypeProperties> pathEqualsToProperties = new LinkedHashMap<>();
    private final PathFragmentToTypePropertiesMapper pathStartsWithProperties;
    private final PathFragmentToTypePropertiesMapper pathContainsProperties;
    private final TypeProperties pathOtherProperties;
    private final TypeProperties allProperties;

    private final LoggingOption loggingOption;

    // public for testing
    public final CallerIdSupplierByTypeFactory callerIdSupplierByTypeFactory;

    @Override
    @NonNull
    public LoggingOption getLoggingOption() {
        return loggingOption;
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
    TypeProperties getPathBasedProperties( String servletPath ) { // Method shows how the search algorithm works!
        TypeProperties pathProperties;
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
                                                                       TypeProperties propsPath, TypeProperties propsAll ) {
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
     * @param tps                   if empty it throws an error
     * @throws RateLimitingConfigException if any of the TypeProperties are bad or collide with another or basic filtering is not included!
     */
    public InternalLimiterFactoriesSupplierImpl( AuthorizationCredentialIdExtractor credentialIdExtractor,
                                                 LoggingOption loggingOption, Collection<TypeProperties> tps ) {
        callerIdSupplierByTypeFactory = CallerIdSupplierByTypeFactoryFactory.from( credentialIdExtractor );
        this.loggingOption = LoggingOption.deNull( loggingOption );

        Map<String, TypeProperties> propertiesByName = new HashMap<>(); // Track dups
        Map<String, PathFragmentToTypeProperties> ptfStartsWiths = new HashMap<>(); // Track dups
        Map<String, PathFragmentToTypeProperties> ptfContains = new HashMap<>(); // Track dups
        TypeProperties pathOtherProperties = null;
        TypeProperties allProperties = null;
        for ( TypeProperties newProperties : tps ) {
            if ( newProperties != null ) {
                checkDuplicateName( propertiesByName, newProperties );

                List<PathSelector> selectors = newProperties.pathSelectors();
                for ( PathSelector selector : selectors ) {
                    PathMatchType pmType = selector.getType();

                    switch ( pmType ) {
                        case Equals:
                            checkDuplicatePathProperties( selector, pathEqualsToProperties, newProperties );
                            break;
                        case StartsWith:
                            checkDuplicatePathLBPTProperties( selector, ptfStartsWiths, newProperties );
                            break;
                        case Contains:
                            checkDuplicatePathLBPTProperties( selector, ptfContains, newProperties );
                            break;
                        case Other:
                            pathOtherProperties = checkDuplicateSpecial( selector, pathOtherProperties, newProperties );
                            break;
                        case All:
                            allProperties = checkDuplicateSpecial( selector, allProperties, newProperties );
                            break;
                        default:
                            throw new RateLimitingConfigException( "Unexpected PathMatchType '" + pmType + "' on: " + newProperties.name() );
                    }
                }
            }
        }
        pathStartsWithProperties = new PathFragmentToTypePropertiesMapper( String::startsWith, ptfStartsWiths.values() );
        pathContainsProperties = new PathFragmentToTypePropertiesMapper( String::contains, ptfContains.values() );
        this.pathOtherProperties = pathOtherProperties;
        this.allProperties = allProperties;
        assertAllPathsCovered();
    }

    private void assertAllPathsCovered() {
        String noOtherError = checkHasGlobal( "Other", pathOtherProperties );
        String noAllError = checkHasGlobal( "All", allProperties );
        if ( (noOtherError != null) && (noAllError != null) ) {
            throw new RateLimitingConfigException( "All paths not limited: " + noOtherError + " AND " + noAllError );
        }
    }

    private static String checkHasGlobal( String name, TypeProperties Properties ) {
        if ( Properties == null ) {
            return name + " not in configuration";
        }
        if ( !Properties.hasGlobal() ) {
            return name + " does not have 'global' limits";
        }
        return null; // Happy case!
    }

    private static void checkDuplicateName( Map<String, TypeProperties> PropertiesByName, TypeProperties newProperties ) {
        String name = newProperties.name();
        TypeProperties prevProperties = PropertiesByName.get( name );
        if ( prevProperties != null ) {
            throw new RateLimitingConfigException( "Duplicate named ('" + name + "') Rate Limiting configurations" );
        }
        PropertiesByName.put( name, newProperties );
    }

    private static TypeProperties checkDuplicateSpecial( PathSelector selector, TypeProperties prevProperties, TypeProperties newProperties ) {
        if ( prevProperties != null ) {
            errorDupProperties( selector, prevProperties, newProperties );
        }
        return newProperties;
    }

    private static void checkDuplicatePathProperties( PathSelector selector, Map<String, TypeProperties> map, TypeProperties newProperties ) {
        String path = selector.getPath();
        TypeProperties prevProperties = map.get( path );
        if ( prevProperties != null ) {
            errorDupProperties( selector, prevProperties, newProperties );
        }
        map.put( path, newProperties );
    }

    private static void checkDuplicatePathLBPTProperties( PathSelector selector, Map<String, PathFragmentToTypeProperties> map, TypeProperties newProperties ) {
        String path = selector.getPath();
        PathFragmentToTypeProperties prevPathToProperties = map.get( path );
        if ( prevPathToProperties != null ) {
            errorDupProperties( selector, prevPathToProperties.getProperties(), newProperties );
        }
        map.put( path, new PathFragmentToTypeProperties( path, newProperties ) );
    }

    private static void errorDupProperties( PathSelector selector, TypeProperties prevProperties, TypeProperties newProperties ) {
        throw new RateLimitingConfigException( "Duplicate Properties Properties (pathSelector: " + selector + ") registered for: " +
                                               prevProperties.name() + " and " + newProperties.name() );
    }

    @SuppressWarnings("SameParameterValue")
    private static void appendTo( StringBuilder sb, PathMatchType type, Map<String, TypeProperties> pathProperties ) {
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
    private static void appendTo( StringBuilder sb, PathMatchType type, TypeProperties properties ) {
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

    private static void appendPropertiesWithPath( StringBuilder sb, String path, TypeProperties properties ) {
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
