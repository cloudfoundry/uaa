package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Singleton;
import org.cloudfoundry.identity.uaa.ratelimiting.util.SourcedFile;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

import static org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus.*;

@Getter
public class InitialConfig {
    public static final List<String> ENVIRONMENT_CONFIG_LOCAL_DIRS = List.of( "CLOUDFOUNDRY_CONFIG_PATH", "UAA_CONFIG_PATH", "RateLimiterConfigDir" );
    public static final String ENVIRONMENT_CONFIG_URL = "RateLimiterConfigUrl";
    public static final String LOCAL_CONFIG_FILE = "RateLimiterConfig.yml";

    public static final Singleton<InitialConfig> SINGLETON =
            new Singleton<>( InitialConfig::create );

    private static final String PRIMARY_DYNAMIC_CONFIG_URL = StringUtils.normalizeToNull( System.getenv( ENVIRONMENT_CONFIG_URL ) );

    private final Exception initialError;
    private final String dynamicUpdateURL;
    private final YamlConfigFileDTO localConfigFileDTO;
    private final RateLimitingFactoriesSupplierWithStatus configurationWithStatus;

    // packageFriendly for Testing
    InitialConfig( Exception initialError, String dynamicUpdateURL,
                   YamlConfigFileDTO localConfigFileDTO,
                   RateLimitingFactoriesSupplierWithStatus configurationWithStatus ) {
        this.initialError = initialError;
        this.dynamicUpdateURL = dynamicUpdateURL;
        this.localConfigFileDTO = localConfigFileDTO;
        this.configurationWithStatus = configurationWithStatus;
    }

    public boolean isRateLimitingEnabled() {
        return (configurationWithStatus != null) && configurationWithStatus.isRateLimitingEnabled();
    }

    // packageFriendly for Testing
    static InitialConfig create() {
        return create( PRIMARY_DYNAMIC_CONFIG_URL, locateAndLoadLocalConfigFile(), MillisTimeSupplier.SYSTEM );
    }

    private static SourcedFile locateAndLoadLocalConfigFile() {
        return clean( SourcedFile.locateAndLoadLocalFile( LOCAL_CONFIG_FILE, getLocalConfigDirs( ENVIRONMENT_CONFIG_LOCAL_DIRS, System::getenv ) ) );
    }

    @SuppressWarnings("SameParameterValue")
    // packageFriendly for Testing
    static String[] getLocalConfigDirs( List<String> dirProxies, Function<String, String> unProxyFunction ) {
        return dirProxies.stream()
                .map( StringUtils::normalizeToNull ).filter( Objects::nonNull )
                .map( unProxyFunction )
                .map( StringUtils::normalizeToNull ).filter( Objects::nonNull )
                .toArray( String[]::new );
    }

    // packageFriendly for Testing
    static SourcedFile clean( SourcedFile sourcedFile ) {
        if ( sourcedFile == null ) {
            return null;
        }
        String str = BindYaml.removeLeadingEmptyDocuments( sourcedFile.getBody() );
        return str.isEmpty() ? null : new SourcedFile( str, sourcedFile.getSource() );
    }

    @SuppressWarnings("SameParameterValue")
    // packageFriendly for Testing
    static InitialConfig create( String url, // primary source of dynamic updates
                                 SourcedFile localConfigFile, MillisTimeSupplier currentTimeSupplier ) {
        if ( (url == null) && (localConfigFile == null) ) { // Leave everything disabled!
            return new InitialConfig( null, null, null,
                                      RateLimitingFactoriesSupplierWithStatus.NO_RATE_LIMITING );
        }
        String errorMsg = null;
        String dynamicUpdateURL = null;
        Exception error = null;
        ExtendedYamlConfigFileDTO dto = null;
        CurrentStatus currentStatus = CurrentStatus.DISABLED;
        UpdateStatus updateStatus = UpdateStatus.DISABLED;
        String sourcedFrom = "InitialConfig";
        if ( localConfigFile != null ) {
            sourcedFrom = localConfigFile.getSource();
            BindYaml<ExtendedYamlConfigFileDTO> bindYaml = new BindYaml<>( ExtendedYamlConfigFileDTO.class, sourcedFrom );
            try {
                dto = parseFile( bindYaml, localConfigFile.getBody() );
                if ( url == null ) {
                    url = dto.getDynamicConfigUrl(); // secondary source of dynamic updates
                }
                currentStatus = CurrentStatus.PENDING;
            }
            catch ( YamlRateLimitingConfigException e ) {
                error = e;
                errorMsg = e.getMessage();
            }
        }
        if ( url != null ) {
            url = StringUtils.normalizeToEmpty( url );
            if ( UrlPrefix.isAcceptable( url ) ) {
                dynamicUpdateURL = url;
                currentStatus = CurrentStatus.PENDING;
                updateStatus = UpdateStatus.PENDING;
            }
        }

        long now = MillisTimeSupplier.deNull( currentTimeSupplier ).now();

        Current current = Current.builder().status( currentStatus ).asOf( now ).error( errorMsg ).build();
        Update update = Update.builder().status( updateStatus ).asOf( now ).build();

        RateLimitingFactoriesSupplierWithStatus configurationWithStatus =
                RateLimitingFactoriesSupplierWithStatus.builder()
                        .supplier( InternalLimiterFactoriesSupplier.NOOP )
                        .status( RateLimiterStatus.builder()
                                         .current( current )
                                         .update( update )
                                         .fromSource( sourcedFrom )
                                         .build() )
                        .build();

        return new InitialConfig( error, dynamicUpdateURL, dto, configurationWithStatus );
    }

    // packageFriendly for Testing
    static ExtendedYamlConfigFileDTO parseFile( BindYaml<ExtendedYamlConfigFileDTO> bindYaml, String fileText ) {
        return bindYaml.bind( fileText );
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class ExtendedYamlConfigFileDTO extends YamlConfigFileDTO {
        private String dynamicConfigUrl;
    }

    enum UrlPrefix {
        https, http;

        public String asPrefix() {
            return name() + "://";
        }

        public static boolean isAcceptable( String url ) {
            if ( url != null ) {
                for ( UrlPrefix up : UrlPrefix.values() ) {
                    if ( url.startsWith( up.asPrefix() ) ) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}