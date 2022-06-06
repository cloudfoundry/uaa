package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.PreDestroy;
import javax.validation.constraints.NotNull;

import org.cloudfoundry.identity.uaa.ratelimiting.core.LoggingOption;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.TypeProperties;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.AuthorizationCredentialIdExtractor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdType;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.LimiterFactorySupplierUpdatable;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.InternalLimiterFactoriesSupplierImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking.LimiterManagerImpl;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.Fetcher;
import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.LoaderLogger;

public class RateLimitingConfigLoader implements Runnable {
    public static final String YAML_FETCH_FAILED = "Fetch Failed";
    public static final String YAML_NULL = "null";
    public static final String YAML_EMPTY = "empty";
    public static final String YAML_DOCUMENT_PREFIX = "document[";
    public static final String YAML_DOCUMENT_WAS = ", document was:\n";
    public static final String YAML_DOCUMENT_DID_NOT_BIND_MIDDLE = "] did not bind to 'YamlConfigDTO'" + YAML_DOCUMENT_WAS;
    public static final String TYPE_PROPERTIES_PROBLEM = "unacceptable/incompatible TypeProperties: ";

    private final Map<String, CredentialIdType> credentialIdTypesByKey = new HashMap<>();
    private final LoaderLogger logger;
    private final Fetcher fetcher;
    private final LimiterFactorySupplierUpdatable supplierUpdatable;
    private final MillisTimeSupplier currentTimeSupplier;
    private final YamlMapper yamlMapper = new YamlMapper();
    private volatile boolean wereDying = false;
    private Thread backgroundThread;

    /**
     * Constructor
     *
     * @param logger            nullable, and if null means NO Rate Limiting
     * @param fetcher           nullable, and if null means NO Rate Limiting
     * @param credentialIdTypes nullable/empty, and if null/empty only Client IP can be used...
     */
    public RateLimitingConfigLoader( LoaderLogger logger, Fetcher fetcher, CredentialIdType... credentialIdTypes ) {
        this( logger, fetcher, LimiterManagerImpl.Singleton.getInstance(), null, false, credentialIdTypes );
    }

    @PreDestroy
    public void dying() {
        wereDying = true;
        if ( backgroundThread != null ) {
            backgroundThread.interrupt();
            supplierUpdatable.shutdownBackgroundProcessing();
        }
    }

    // package friendly and more params for Testing
    RateLimitingConfigLoader( LoaderLogger logger, Fetcher fetcher,
                              @NotNull LimiterFactorySupplierUpdatable supplierUpdatable,
                              MillisTimeSupplier currentTimeSupplier, boolean noBackgroundProcessor,
                              CredentialIdType... credentialIdTypes ) {
        this.logger = logger;
        this.fetcher = fetcher;
        this.supplierUpdatable = supplierUpdatable;
        this.currentTimeSupplier = MillisTimeSupplier.deNull( currentTimeSupplier );
        if ( fetcher != null ) { // Rate Limiting active
            populateCredentialIdTypes( credentialIdTypes );
            yamlMapper.tps = TypeProperties.DEFAULT_LIST;
            supplierUpdatable.update( yamlMapper.createUpdatable() );
            logger.logUpdate( "Default Rate Limits loaded" );
            if ( !noBackgroundProcessor ) {
                supplierUpdatable.startBackgroundProcessing();
                backgroundThread = new Thread( this );
                backgroundThread.setName( "TypesPropertiesLoaderProcess" );
                backgroundThread.setDaemon( true );
                backgroundThread.start();
            }
        }
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

    // package friendly for testing
    boolean hasCredentialIdTypes() {
        return !credentialIdTypesByKey.isEmpty();
    }

    // package friendly for testing
    boolean checkForUpdatedProperties() {
        InternalLimiterFactoriesSupplierImpl factorySupplier = yamlMapper.process();
        if ( factorySupplier != null ) {
            supplierUpdatable.update( factorySupplier );
            logger.logUpdate( factorySupplier.typePropertiesPathOptionsCount() );
            return true;
        }
        return false;
    }

    @SuppressWarnings("BusyWait")
    @Override
    public void run() {
        while ( !wereDying ) {
            long nextRunTime = currentTimeSupplier.now() + 15000;
            try {
                Thread.sleep( 2000 ); // check every 15 seconds (2 here & rest below)
                checkForUpdatedProperties();
                Thread.sleep( nextRunTime - currentTimeSupplier.now() );
            }
            catch ( InterruptedException e ) {
                // As it is a Daemon, ignore InterruptedException and check if "wereDying"!
            }
            catch ( RateLimitingConfigException e ) {
                logger.logError( e );
            }
            catch ( RuntimeException e ) {
                logger.logUnhandledError( e ); // Log everything else
            }
        }
    }

    private class YamlMapper {
        private String lastYAML = "";
        private String yamlString;
        private AuthorizationCredentialIdExtractor credentialIdExtractor;
        private LoggingOption loggingOption;
        public List<TypeProperties> tps;

        public InternalLimiterFactoriesSupplierImpl process() {
            // re-initialize
            credentialIdExtractor = null;
            tps = new ArrayList<>();

            loadYamlString();
            if ( !shouldUpdate() ) {  // check for change
                return null;
            }
            parseYaml( yamlString );
            return createUpdatable();
        }

        public InternalLimiterFactoriesSupplierImpl createUpdatable() {
            InternalLimiterFactoriesSupplierImpl factorySupplier;
            try {
                factorySupplier = new InternalLimiterFactoriesSupplierImpl( credentialIdExtractor, loggingOption, tps );
            }
            catch ( RateLimitingConfigException e ) {
                throw new YamlRateLimitingConfigException( yamlString, TYPE_PROPERTIES_PROBLEM + e.getMessage(), e );
            }
            return factorySupplier;
        }

        private boolean shouldUpdate() {
            if ( lastYAML.equals( yamlString ) ) {
                return false;
            }
            lastYAML = yamlString; // update last state to force wait for another change (minimize dup errors)
            return true;
        }

        private void loadYamlString() {
            try {
                yamlString = fetcher.fetchYaml();
            }
            catch ( IOException e ) {
                throw new YamlRateLimitingConfigException( null, YAML_FETCH_FAILED, e );
            }
            if ( yamlString == null ) {
                throw new YamlRateLimitingConfigException( null, YAML_NULL );
            }
            yamlString = yamlString.trim();
            if ( yamlString.isEmpty() ) {
                throw new YamlRateLimitingConfigException( yamlString, YAML_EMPTY );
            }
        }

        /*
         * Note: Manually chunks the file into "documents" (by splitting on "---") so that
         * the individual errors can be better reported with a "document" index (index 0, is
         * everything before the first "---")!
         *
         * The use of "---" ("c-directives-end" - document sep) WITHOUT any regard
         * for line breaks (new line characters) to chunk the yaml, is a little
         * dangerous - specifically if the "---" ("c-directives-end" - document sep) is
         * placed in a comment, scalar string, or value!
         *
         * However, do to the simplicity of the configuration of
         * the Type Properties, it does not seam to be a significant risk!
         */
        private void parseYaml( String yamlString ) {
            String[] docs = yamlString.split( "---" ); // "c-directives-end"s (document sep)
            Yaml yaml = new Yaml( new Constructor( YamlConfigDTO.class ) );
            for ( int i = 0; i < docs.length; i++ ) {
                String doc = docs[i].trim();
                if ( !doc.isEmpty() ) {
                    YamlConfigDTO dto;
                    try {
                        dto = yaml.load( doc );
                    }
                    catch ( RuntimeException e ) {
                        String message = YAML_DOCUMENT_PREFIX + i + YAML_DOCUMENT_DID_NOT_BIND_MIDDLE + doc + "\n";
                        throw new YamlRateLimitingConfigException( yamlString, message, e );
                    }

                    try {
                        processDTO( dto );
                    }
                    catch ( RateLimitingConfigException e ) {
                        String message = YAML_DOCUMENT_PREFIX + i + "] " + e.getMessage() + YAML_DOCUMENT_WAS + doc + "\n";
                        throw new YamlRateLimitingConfigException( yamlString, message );
                    }
                }
            }
        }

        private void processDTO( YamlConfigDTO dto ) {
            List<String> definitions = new ArrayList<>( 3 );
            add( definitions, dto.toTypeProperties() );
            add( definitions, dto.toCredentialIdDefinition() );
            add( definitions, dto.toLoggingOption() );

            int found = definitions.size();
            if ( found < 2 ) {
                return; // none or 1 is OK!
            }
            StringBuilder sb = new StringBuilder().append( "Contained" );
            if ( found == 2 ) {
                sb.append( " both" );
            }
            sb.append( " a " ).append( definitions.get( 0 ) );
            for ( int i = 1; i < definitions.size(); i++ ) {
                sb.append( " and a " ).append( definitions.get( i ) );
            }
            sb.append( " definitions" );
            if ( found > 2 ) {
                sb.append( ", but only one allowed per document" );
            }
            throw new RateLimitingConfigException( sb.toString() );
        }

        private void add( List<String> definitions, TypeProperties tp ) {
            if ( tp != null ) {
                tps.add( tp );
                definitions.add( "'limiter' (name == '" + tp.name() + "')" );
            }
        }

        private void add( List<String> definitions, YamlCredentialIdDefinition credentialIdDefinition ) {
            if ( credentialIdDefinition != null ) {
                String key = credentialIdDefinition.getKey();
                String definition = "'credentialID' (key == '" + key + "')";
                definitions.add( definition );
                if ( credentialIdExtractor != null ) {
                    throw new RateLimitingConfigException( "Second " + definition );
                }
                CredentialIdType type = credentialIdTypesByKey.get( key );
                if ( type == null ) {
                    throw new RateLimitingConfigException( definition + " not found, " +
                                                           StringUtils.options( "registered type",
                                                                                credentialIdTypesByKey.keySet() ) );
                }
                credentialIdExtractor = type.factory( credentialIdDefinition.getPostKeyConfig() );
            }
        }

        private void add( List<String> definitions, YamlLoggingOption loggingOption ) {
            if ( loggingOption != null ) {
                String value = loggingOption.getValue();
                String definition = "'loggingOption' (value == '" + value + "')";
                definitions.add( definition );
                if ( this.loggingOption != null ) {
                    throw new RateLimitingConfigException( "Second " + definition );
                }
                this.loggingOption = LoggingOption.valueFor( value );
                if ( this.loggingOption == null ) {
                    throw new RateLimitingConfigException( definition + " not found, " +
                                                           StringUtils.options( "valid option",
                                                                                (Object[])LoggingOption.values() ) );
                }
            }
        }
    }
}
