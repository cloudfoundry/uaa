package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

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
    public static final String ENVIRONMENT_CONFIG_URL = "RateLimiterConfigUrl";
    public static final String LOCAL_RESOURCE_CONFIG_FILE = "RateLimiterConfig.yml";

    public static final Singleton<InitialConfig> SINGLETON =
            new Singleton<>( InitialConfig::create );

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
        return create( StringUtils.normalizeToNull( System.getenv( ENVIRONMENT_CONFIG_URL ) ), // primary source of dynamic updates
                       loadFile( getFileInputStream() ),
                       MillisTimeSupplier.SYSTEM );
    }

    @SuppressWarnings("SameParameterValue")
    // packageFriendly for Testing
    static InitialConfig create( String url, // primary source of dynamic updates
                                 String fileText, MillisTimeSupplier currentTimeSupplier ) {
        if ( (url == null) && (fileText == null) ) { // Leave everything disabled!
            return new InitialConfig( null, null, null,
                                      RateLimitingFactoriesSupplierWithStatus.NO_RATE_LIMITING );
        }
        String errorMsg = null;
        String dynamicUpdateURL = null;
        Exception error = null;
        ExtendedYamlConfigFileDTO dto = null;
        CurrentStatus currentStatus = CurrentStatus.DISABLED;
        UpdateStatus updateStatus = UpdateStatus.DISABLED;
        if ( fileText != null ) {
            try {
                dto = parseFile( fileText );
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
                                         .fromSource( "InitialConfig" )
                                         .build() )
                        .build();

        return new InitialConfig( error, dynamicUpdateURL, dto, configurationWithStatus );
    }

    // packageFriendly for Testing
    static ExtendedYamlConfigFileDTO parseFile( String fileText ) {
        return new BindYaml( "Resource file(/" + LOCAL_RESOURCE_CONFIG_FILE + ")" )
                .bind( ExtendedYamlConfigFileDTO.class, fileText );
    }

    static String loadFile( InputStream is ) {
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
            throw new IllegalStateException( "Unable to read resource (root) file: " + LOCAL_RESOURCE_CONFIG_FILE, e );
        }
        String str = sb.toString().stripLeading();
        if (str.startsWith( "---" )) {
            str = str.substring( 3 ).stripLeading();
            if (str.startsWith( "{}" )) {
                str = str.substring( 2 ).stripLeading();
            }
        }
        return str.isEmpty() ? null : str;
    }

    private static InputStream getFileInputStream() {
        return InitialConfig.class.getClassLoader().getResourceAsStream( "/" + LOCAL_RESOURCE_CONFIG_FILE );
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