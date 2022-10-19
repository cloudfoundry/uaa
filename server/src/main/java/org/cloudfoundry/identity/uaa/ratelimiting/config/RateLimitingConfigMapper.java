package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.PathSelector;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.InternalLimiterFactoriesSupplierImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.YamlConfigFileDTO.LimiterMap;

public class RateLimitingConfigMapper {
    public static final String NO_NAME_PROVIDED = "Incomplete Rate Limiting configuration entry - No 'name' provided; in: ";

    private final boolean updatingEnabled;
    private final MillisTimeSupplier currentTimeSupplier;
    private final Map<String, CredentialIdType> credentialIdTypesByKey = new HashMap<>();
    private YamlConfigFileDTO dtoPrevious; // Cached data

    /**
     * Constructor
     *
     * @param credentialIdTypes nullable/empty, and if null/empty only Client IP can be used...
     */
    public RateLimitingConfigMapper( boolean updatingEnabled, CredentialIdType... credentialIdTypes ) {
        this( updatingEnabled, null, credentialIdTypes );
    }

    // package friendly and more params for Testing
    RateLimitingConfigMapper( boolean updatingEnabled, MillisTimeSupplier currentTimeSupplier, CredentialIdType... credentialIdTypes ) {
        this.updatingEnabled = updatingEnabled;
        this.currentTimeSupplier = MillisTimeSupplier.deNull( currentTimeSupplier );
        populateCredentialIdTypes( credentialIdTypes );
    }

    // package friendly for testing
    @SuppressWarnings("unused")
    boolean hasCredentialIdTypes() {
        return !credentialIdTypesByKey.isEmpty();
    }

    public RateLimitingFactoriesSupplierWithStatus map( RateLimitingFactoriesSupplierWithStatus current, String fromSource, YamlConfigFileDTO dto ) {
        if ( (dto == null) || dto.equals( dtoPrevious ) ) {
            return null;
        }
        dtoPrevious = dto;
        ErrorSupplierPair pair;
        try {
            pair = ErrorSupplierPair.with( new Mapper().map( dto ) );
        }
        catch ( RuntimeException e ) {
            pair = ErrorSupplierPair.with( e );
        }
        return pair.map( current, fromSource, updatingEnabled, currentTimeSupplier.now() );
    }

    private void populateCredentialIdTypes( CredentialIdType[] credentialIdTypes ) {
        if ( credentialIdTypes != null ) {
            for ( CredentialIdType type : credentialIdTypes ) {
                if ( type != null ) {
                    if ( null != credentialIdTypesByKey.put( type.key(), type ) ) {
                        throw new Error( "CredentialIdType key '" + type.key() + "' -- Coding error!" );
                    }
                }
            }
        }
    }

    private class Mapper {
        public InternalLimiterFactoriesSupplier map( YamlConfigFileDTO dto )
                throws RateLimitingConfigException {

            AuthorizationCredentialIdExtractor credentialIdExtractor = parseCredentialIdDefinition( dto.getCredentialID() );
            LoggingOption loggingOption = parseLoggingOption( dto.getLoggingOption() );
            List<LimiterMapping> limiterMappings = new LimiterMapsMapper().parse( dto.getLimiterMappings() );

            return new InternalLimiterFactoriesSupplierImpl( credentialIdExtractor, loggingOption, limiterMappings );
        }

        private class LimiterMapsMapper {
            private final Map<String, LimiterMapping> limiterMappingsByName = new HashMap<>();
            private final Map<PathSelector, String> limiterNamesByPathSelector = new HashMap<>();
            private final List<LimiterMapping> limiterMappings = new ArrayList<>();

            public List<LimiterMapping> parse( List<LimiterMap> limiterMaps ) {
                if ( limiterMaps != null ) {
                    for ( int i = 0; i < limiterMaps.size(); i++ ) {
                        try {
                            validateAndAdd( parse( limiterMaps.get( i ) ) );
                        }
                        catch ( Exception e ) {
                            throw new RateLimitingConfigException( "Error in limiterMappings[" + i + "] of: " + e.getMessage(), e );
                        }
                    }
                }
                return limiterMappings;
            }

            private void validateAndAdd( LimiterMapping mapping ) {
                if ( mapping != null ) {
                    String name = mapping.name();
                    checkDupName( mapping, name );
                    for ( PathSelector ps : mapping.pathSelectors() ) {
                        checkDupPath( name, ps );
                    }
                    limiterMappings.add( mapping );
                }
            }

            private void checkDupName( LimiterMapping mapping, String name ) {
                LimiterMapping existing = limiterMappingsByName.put( name, mapping );
                if ( existing != null ) {
                    throw new RateLimitingConfigException( "Duplicate Name (" + name + ") other's data (" + existing + ")" );
                }
            }

            private void checkDupPath( String name, PathSelector ps ) {
                String existingName = limiterNamesByPathSelector.put( ps, name );
                if ( existingName != null ) {
                    throw new RateLimitingConfigException( "Duplicate PathSelector (" + ps + ") other's name (" + existingName + ")" );
                }
            }

            private LimiterMapping parse( LimiterMap limiterMap ) {
                if ( (limiterMap == null) || limiterMap.normalizeAndCheckEmpty() ) {
                    return null;
                }

                String name = limiterMap.getName();
                if ( name == null ) {
                    throw new RateLimitingConfigException( NO_NAME_PROVIDED + limiterMap );
                }
                return LimiterMapping.builder()
                        .name( name )
                        .global( limiterMap.getGlobal() )
                        .withCallerCredentialsID( limiterMap.getWithCallerCredentialsID() )
                        .withCallerRemoteAddressID( limiterMap.getWithCallerRemoteAddressID() )
                        .withoutCallerID( limiterMap.getWithoutCallerID() )
                        .pathSelectors( limiterMap.getPathSelectors() )
                        .build();
            }
        }
    }

    private AuthorizationCredentialIdExtractor parseCredentialIdDefinition( String credentialIdDefinition ) {
        YamlCredentialIdDefinition definition = YamlCredentialIdDefinition.from( credentialIdDefinition );
        if ( definition != null ) {
            CredentialIdType type = credentialIdTypesByKey.get( definition.getKey() );
            if ( type == null ) {
                throw new RateLimitingConfigException( definition + " not found, " +
                                                       StringUtils.options( "registered type",
                                                                            credentialIdTypesByKey.keySet().toArray() ) );
            }
            return type.factory( definition.getPostKeyConfig() );
        }
        return null;
    }

    private LoggingOption parseLoggingOption( String loggingOptionDefinition ) {
        loggingOptionDefinition = StringUtils.normalizeToNull( loggingOptionDefinition );
        if ( loggingOptionDefinition != null ) {
            LoggingOption loggingOption = LoggingOption.valueFor( loggingOptionDefinition );
            if ( loggingOption == null ) {
                throw new RateLimitingConfigException( loggingOptionDefinition + " not found, " +
                                                       StringUtils.options( "valid option",
                                                                            LoggingOption.values() ) );
            }
            return loggingOption;
        }
        return LoggingOption.OnlyLimited;
    }
}
