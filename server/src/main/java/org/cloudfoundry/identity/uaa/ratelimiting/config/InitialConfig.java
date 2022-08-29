package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.List;
import java.util.Objects;
import java.util.function.UnaryOperator;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.MillisTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Singleton;
import org.cloudfoundry.identity.uaa.ratelimiting.util.SourcedFile;


import static org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus.*;

@Getter
public class InitialConfig {
    public static final List<String> ENVIRONMENT_CONFIG_LOCAL_DIRS = List.of( "CLOUDFOUNDRY_CONFIG_PATH", "UAA_CONFIG_PATH", "RateLimiterConfigDir" );
    public static final String LOCAL_CONFIG_FILE = "RateLimiterConfig.yml";

    public static final Singleton<InitialConfig> SINGLETON =
            new Singleton<>( InitialConfig::create );

    private final Exception initialError;
    private final YamlConfigFileDTO localConfigFileDTO;
    private final RateLimitingFactoriesSupplierWithStatus configurationWithStatus;

    // packageFriendly for Testing
    InitialConfig( Exception initialError, YamlConfigFileDTO localConfigFileDTO,
                   RateLimitingFactoriesSupplierWithStatus configurationWithStatus ) {
        this.initialError = initialError;
        this.localConfigFileDTO = localConfigFileDTO;
        this.configurationWithStatus = configurationWithStatus;
    }

    public boolean isRateLimitingEnabled() {
        return (configurationWithStatus != null) && configurationWithStatus.isRateLimitingEnabled();
    }

    // packageFriendly for Testing
    static InitialConfig create() {
        return create( locateAndLoadLocalConfigFile(), MillisTimeSupplier.SYSTEM );
    }

    private static SourcedFile locateAndLoadLocalConfigFile() {
        return clean( SourcedFile.locateAndLoadLocalFile( LOCAL_CONFIG_FILE, getLocalConfigDirs( ENVIRONMENT_CONFIG_LOCAL_DIRS, System::getProperty ) ) );
    }

    @SuppressWarnings("SameParameterValue")
    // packageFriendly for Testing
    static String[] getLocalConfigDirs( List<String> dirProxies, UnaryOperator<String> unProxyFunction ) {
        return dirProxies.stream()
                .map( StringUtils::stripToNull ).filter( Objects::nonNull )
                .map( unProxyFunction )
                .map( StringUtils::stripToNull ).filter( Objects::nonNull )
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
    static InitialConfig create( SourcedFile localConfigFile, MillisTimeSupplier currentTimeSupplier ) {
        if (localConfigFile == null) { // Leave everything disabled!
            return new InitialConfig( null, null, RateLimitingFactoriesSupplierWithStatus.NO_RATE_LIMITING );
        }
        String errorMsg = null;
        Exception error = null;
        ExtendedYamlConfigFileDTO dto = null;
        CurrentStatus currentStatus = CurrentStatus.DISABLED;

        String sourcedFrom = localConfigFile.getSource();
        BindYaml<ExtendedYamlConfigFileDTO> bindYaml = new BindYaml<>( ExtendedYamlConfigFileDTO.class, sourcedFrom );
        try {
            dto = parseFile( bindYaml, localConfigFile.getBody() );
            currentStatus = CurrentStatus.PENDING;
        }
        catch ( YamlRateLimitingConfigException e ) {
            error = e;
            errorMsg = e.getMessage();
        }

        long now = MillisTimeSupplier.deNull( currentTimeSupplier ).now();

        Current current = Current.builder().status( currentStatus ).asOf( now ).error( errorMsg ).build();

        RateLimitingFactoriesSupplierWithStatus configurationWithStatus =
                RateLimitingFactoriesSupplierWithStatus.builder()
                        .supplier( InternalLimiterFactoriesSupplier.NOOP )
                        .status( RateLimiterStatus.builder()
                                         .current( current )
                                         .fromSource( sourcedFrom )
                                         .build() )
                        .build();

        return new InitialConfig( error, dto, configurationWithStatus );
    }

    // packageFriendly for Testing
    static ExtendedYamlConfigFileDTO parseFile( BindYaml<ExtendedYamlConfigFileDTO> bindYaml, String fileText ) {
        return bindYaml.bind( fileText );
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @EqualsAndHashCode
    public static class ExtendedYamlConfigFileDTO extends YamlConfigFileDTO {
        private String dynamicConfigUrl;
    }
}