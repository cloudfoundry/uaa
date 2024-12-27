package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.PathSelector;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.InternalLimiterFactoriesSupplierImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtilities;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.YamlConfigFileDTO.LimiterMap;

public class RateLimitingConfigMapperImpl implements RateLimitingConfigMapper {
    static final String CREDENTIAL_ID_NOT_FOUND_PREFIX = "credentialID not found, provided '";
    static final String LOGGING_OPTION_NOT_FOUND_PREFIX = "loggingOption not found, provided '";
    static final String ERROR_IN_LIMITER_MAPPINGS_PREFIX = "Error in limiterMappings[";

    static final String NO_NAME_PROVIDED_PREFIX = "No 'name' provided; in: ";
    static final String DUPLICATE_PATH_SELECTOR_PREFIX = "Duplicate PathSelector (";
    static final String DUPLICATE_NAME_PREFIX = "Duplicate Name (";

    private final NanoTimeSupplier currentTimeSupplier;
    private final Map<String, CredentialIdType> credentialIdTypesByKey = new HashMap<>();
    // package friendly for testing
    YamlConfigFileDTO dtoPrevious; // Cached data

    /**
     * Constructor
     *
     * @param credentialIdTypes nullable/empty, and if null/empty only Client IP can be used...
     */
public RateLimitingConfigMapperImpl(CredentialIdType... credentialIdTypes) {
        this(null, credentialIdTypes);
    }

    // package friendly and more params for Testing
    RateLimitingConfigMapperImpl(NanoTimeSupplier currentTimeSupplier, CredentialIdType... credentialIdTypes) {
        this.currentTimeSupplier = NanoTimeSupplier.deNull(currentTimeSupplier);
        populateCredentialIdTypes(credentialIdTypes);
    }

    // package friendly for testing
    @SuppressWarnings("unused")
    int getCredentialIdTypeCount() {
        return credentialIdTypesByKey.size();
    }

    @Override
    public RateLimitingFactoriesSupplierWithStatus map(RateLimitingFactoriesSupplierWithStatus current, String fromSource, YamlConfigFileDTO dto) {
        return checkNoChange(dto) ? null : createErrorSupplierPair(dto).map(current, fromSource, TimeUnit.NANOSECONDS.toMillis(currentTimeSupplier.now()));
    }

    // package friendly for testing
    boolean checkNoChange(YamlConfigFileDTO dto) {
        if ((dto == null) || dto.equals(dtoPrevious)) {
            return true;
        }
        dtoPrevious = dto;
        return false;
    }

    // package friendly for testing
    ErrorSupplierPair createErrorSupplierPair(YamlConfigFileDTO dto) {
        try {
            return ErrorSupplierPair.with(createSupplier(dto));
        }
        catch (RuntimeException e) {
            return ErrorSupplierPair.with(e);
        }
    }

    // package friendly for testing
    InternalLimiterFactoriesSupplier createSupplier(YamlConfigFileDTO dto) {
        AuthorizationCredentialIdExtractor credentialIdExtractor = parseCredentialIdDefinition(dto.getCredentialID());
        LoggingOption loggingOption = parseLoggingOption(dto.getLoggingOption());
        List<LimiterMapping> limiterMappings = new LimiterMapsMapper().parse(dto.getLimiterMappings());

        if (limiterMappings.isEmpty()) {
            throw new RateLimitingConfigException( "No limiterMappings" );
        }
        return new InternalLimiterFactoriesSupplierImpl( credentialIdExtractor, loggingOption, limiterMappings );
    }

    private AuthorizationCredentialIdExtractor parseCredentialIdDefinition(String credentialIdDefinition) {
        YamlCredentialIdDefinition definition = YamlCredentialIdDefinition.from(credentialIdDefinition);
        if (definition != null) {
            CredentialIdType type = credentialIdTypesByKey.get(definition.getKey());
            if (type == null) {
                throw new RateLimitingConfigException( CREDENTIAL_ID_NOT_FOUND_PREFIX + definition + "'; " +
                        StringUtilities.options("registered type", credentialIdTypesByKey.keySet().toArray()) );
            }
            return type.factory(definition.getPostKeyConfig());
        }
        return null;
    }

    private LoggingOption parseLoggingOption(String loggingOptionDefinition) {
        loggingOptionDefinition = StringUtils.stripToNull(loggingOptionDefinition);
        if (loggingOptionDefinition != null) {
            LoggingOption loggingOption = LoggingOption.valueFor(loggingOptionDefinition);
            if (loggingOption == null) {
                throw new RateLimitingConfigException( LOGGING_OPTION_NOT_FOUND_PREFIX + loggingOptionDefinition + "'; " +
                        StringUtilities.options("valid option", LoggingOption.values()) );
            }
            return loggingOption;
        }
        return LoggingOption.OnlyLimited;
    }

    private static class LimiterMapsMapper {
        private final Map<String, LimiterMapping> limiterMappingsByName = new HashMap<>();
        private final Map<PathSelector, String> limiterNamesByPathSelector = new HashMap<>();
        private final List<LimiterMapping> limiterMappings = new ArrayList<>();

        public List<LimiterMapping> parse(List<LimiterMap> limiterMaps) {
            if (limiterMaps != null) {
                for (int i = 0; i < limiterMaps.size(); i++) {
                    try {
                        validateAndAdd(parse(limiterMaps.get(i)));
                    }
                    catch (Exception e) {
                        throw new RateLimitingConfigException( ERROR_IN_LIMITER_MAPPINGS_PREFIX + i + "] of: " + e.getMessage(), e );
                    }
                }
            }
            return limiterMappings;
        }

        private void validateAndAdd(LimiterMapping mapping) {
            if (mapping != null) {
                String name = mapping.name();
                checkDupName(mapping, name);
                for (PathSelector ps : mapping.pathSelectors()) {
                    checkDupPath(name, ps);
                }
                limiterMappings.add(mapping);
            }
        }

        private void checkDupName(LimiterMapping mapping, String name) {
            LimiterMapping existing = limiterMappingsByName.put(name, mapping);
            if (existing != null) {
                throw new RateLimitingConfigException( DUPLICATE_NAME_PREFIX + name + ") other's data (" + existing + ")" );
            }
        }

        private void checkDupPath(String name, PathSelector ps) {
            String existingName = limiterNamesByPathSelector.put(ps, name);
            if (existingName != null) {
                throw new RateLimitingConfigException( DUPLICATE_PATH_SELECTOR_PREFIX + ps + ") other's name (" + existingName + ")" );
            }
        }

        private LimiterMapping parse(LimiterMap limiterMap) {
            if ((limiterMap == null) || limiterMap.normalizeAndCheckEmpty()) {
                return null;
            }

            String name = limiterMap.getName();
            if (name == null) {
                throw new RateLimitingConfigException( NO_NAME_PROVIDED_PREFIX + limiterMap );
            }
            return LimiterMapping.builder()
                    .name(name)
                    .global(limiterMap.getGlobal())
                    .withCallerCredentialsID(limiterMap.getWithCallerCredentialsID())
                    .withCallerRemoteAddressID(limiterMap.getWithCallerRemoteAddressID())
                    .withoutCallerID(limiterMap.getWithoutCallerID())
                    .pathSelectors(limiterMap.getPathSelectors())
                    .build();
        }
    }

    private void populateCredentialIdTypes(CredentialIdType[] credentialIdTypes) {
        if (credentialIdTypes != null) {
            for (CredentialIdType type : credentialIdTypes) {
                if (type != null && null != credentialIdTypesByKey.put(type.key(), type)) {
                    throw new Error( "CredentialIdType key '" + type.key() + "' -- Coding error!" );
                }
            }
        }
    }
}
