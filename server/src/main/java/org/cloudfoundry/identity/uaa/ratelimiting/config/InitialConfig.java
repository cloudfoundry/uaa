package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Singleton;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

import static org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus.*;

@Getter
public class InitialConfig {
    public static final String[] ENVIRONMENT_CONFIG_LOCAL_DIRS = {"CLOUDFOUNDRY_CONFIG_PATH", "UAA_CONFIG_PATH", "RateLimiterConfigDir"};
    public static final String ENVIRONMENT_CONFIG_URL = "RateLimiterConfigUrl";
    public static final String LOCAL_RESOURCE_CONFIG_FILE = "RateLimiterConfig.yml";

    public static final Singleton<InitialConfig> SINGLETON =
            new Singleton<>( InitialConfig::create );

    private static final String PRIMARY_DYNAMIC_CONFIG_URL = StringUtils.normalizeToNull( System.getenv( ENVIRONMENT_CONFIG_URL ) );

    private final Exception initialError;
    private final String dynamicUpdateURL;
    private final YamlConfigFileDTO localResourceConfigFileDTO;
    private final RateLimitingFactoriesSupplierWithStatus configurationWithStatus;

    // packageFriendly for Testing
    InitialConfig( Exception initialError, String dynamicUpdateURL,
                   YamlConfigFileDTO localResourceConfigFileDTO,
                   RateLimitingFactoriesSupplierWithStatus configurationWithStatus ) {
        this.initialError = initialError;
        this.dynamicUpdateURL = dynamicUpdateURL;
        this.localResourceConfigFileDTO = localResourceConfigFileDTO;
        this.configurationWithStatus = configurationWithStatus;
    }

    public boolean isRateLimitingEnabled() {
        return (configurationWithStatus != null) && configurationWithStatus.isRateLimitingEnabled();
    }

    // packageFriendly for Testing
    static InitialConfig create() {
        return create( PRIMARY_DYNAMIC_CONFIG_URL, locateAndLoadLocalConfigFile(), MillisTimeSupplier.SYSTEM );
    }

    @AllArgsConstructor
    static class SourcedFile {
        String body;
        String source;
    }

    // packageFriendly for Testing
    static SourcedFile locateAndLoadLocalConfigFile() {
        for ( String envVarDir : ENVIRONMENT_CONFIG_LOCAL_DIRS ) {
            String dir = StringUtils.normalizeToEmpty( System.getenv( envVarDir ) );
            if ( dir.startsWith( "/" ) ) {
                InputStream is = getFileInputStream( dir );
                if ( is != null ) {
                    return loadFile( is, "config file(" + dir + "/" + LOCAL_RESOURCE_CONFIG_FILE + ")" );
                }
            }
        }
        return loadFile( getFileInputStreamFromResources(), "resource file(/" + LOCAL_RESOURCE_CONFIG_FILE + ")" );
    }

    static SourcedFile loadFile( InputStream is, String source ) {
        if ( is == null ) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        try ( InputStreamReader streamReader = new InputStreamReader( is, StandardCharsets.UTF_8 );
              BufferedReader reader = new BufferedReader( streamReader ) ) {

            for ( String line; (line = reader.readLine()) != null; ) {
                sb.append( line ).append( '\n' );
            }
        }
        catch ( IOException e ) {
            throw new IllegalStateException( "Unable to read " + source, e );
        }
        String str = BindYaml.removeLeadingEmptyDocuments( sb.toString() );
        return str.isEmpty() ? null : new SourcedFile( str, source );
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
            sourcedFrom = localConfigFile.source;
            BindYaml<ExtendedYamlConfigFileDTO> bindYaml = new BindYaml<>( ExtendedYamlConfigFileDTO.class, sourcedFrom );
            try {
                dto = parseFile( bindYaml, localConfigFile.body );
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

    private static InputStream getFileInputStreamFromResources() {
        return InitialConfig.class.getClassLoader().getResourceAsStream( "/" + LOCAL_RESOURCE_CONFIG_FILE );
    }

    private static InputStream getFileInputStream( String dir ) {
        try {
            File file = FileSystems.getDefault().getPath( dir, LOCAL_RESOURCE_CONFIG_FILE ).toFile();
            if ( file.isFile() ) {
                return new FileInputStream( file );
            }
        }
        catch ( IOException ignore ) {
            // ignore!
        }
        return null;
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