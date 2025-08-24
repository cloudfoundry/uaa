package org.cloudfoundry.identity.uaa.ratelimiting.config;

import static org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus.Current;
import static org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus.CurrentStatus;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.UnaryOperator;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.RateLimiterStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.InternalLimiterFactoriesSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.internal.common.RateLimitingFactoriesSupplierWithStatus;
import org.cloudfoundry.identity.uaa.ratelimiting.util.NanoTimeSupplier;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Singleton;
import org.cloudfoundry.identity.uaa.ratelimiting.util.SourcedFile;
import org.cloudfoundry.identity.uaa.util.UaaYamlUtils;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
public class InitialConfig {
    public static final List<String> ENVIRONMENT_CONFIG_LOCAL_DIRS = List.of("CLOUDFOUNDRY_CONFIG_PATH", "UAA_CONFIG_PATH", "RateLimiterConfigDir");
    public static final String LOCAL_CONFIG_FILE = "uaa.yml";

    public static final Singleton<InitialConfig> SINGLETON =
            new Singleton<>( InitialConfig::create );

    private final Exception initialError;
    private final YamlConfigFileDTO localConfigFileDTO;
    private final RateLimitingFactoriesSupplierWithStatus configurationWithStatus;

    // packageFriendly for Testing
    InitialConfig(Exception initialError, YamlConfigFileDTO localConfigFileDTO,
            RateLimitingFactoriesSupplierWithStatus configurationWithStatus) {
        this.initialError = initialError;
        this.localConfigFileDTO = localConfigFileDTO;
        this.configurationWithStatus = configurationWithStatus;
    }

    public boolean isRateLimitingEnabled() {
        return (configurationWithStatus != null) && configurationWithStatus.isRateLimitingEnabled();
    }

    // packageFriendly for Testing
    static InitialConfig create() {
        return create(locateAndLoadLocalConfigFile(), NanoTimeSupplier.SYSTEM);
    }

    private static SourcedFile locateAndLoadLocalConfigFile() {
        return clean(SourcedFile.locateAndLoadLocalFile(LOCAL_CONFIG_FILE, getLocalConfigDirs(ENVIRONMENT_CONFIG_LOCAL_DIRS, InitialConfig::getEnvOrProperty)));
    }

    private static String getEnvOrProperty(String key) {
        String retVal = System.getenv(key);
        if (retVal != null) {
            return retVal;
        } else {
            return System.getProperty(key);
        }
    }

    // packageFriendly for Testing
    static String[] getLocalConfigDirs(List<String> dirProxies, UnaryOperator<String> unProxyFunction) {
        return dirProxies.stream()
                .map(StringUtils::stripToNull).filter(Objects::nonNull)
                .map(unProxyFunction)
                .map(StringUtils::stripToNull).filter(Objects::nonNull)
                .toArray(String[]::new);
    }

    // packageFriendly for Testing
    static SourcedFile clean(SourcedFile sourcedFile) {
        if (sourcedFile == null) {
            return null;
        }
        String str = BindYaml.removeLeadingEmptyDocuments(sourcedFile.getBody());
        return str.isEmpty() ? null : new SourcedFile( str, sourcedFile.getSource() );
    }

    // packageFriendly for Testing
    static InitialConfig create(SourcedFile localConfigFile, NanoTimeSupplier currentTimeSupplier) {
        // Leave everything disabled!
        if (localConfigFile == null) {
            return new InitialConfig( null, null, RateLimitingFactoriesSupplierWithStatus.NO_RATE_LIMITING );
        }
        String errorMsg = null;
        Exception error = null;
        UaaYamlConfigFileDTO dto = null;
        CurrentStatus currentStatus = CurrentStatus.DISABLED;

        String sourcedFrom = localConfigFile.getSource();
        BindYaml<UaaYamlConfigFileDTO> bindYaml = new BindYaml<>( UaaYamlConfigFileDTO.class, sourcedFrom );
        try {
            dto = parseFile(bindYaml, localConfigFile.getBody());
            currentStatus = CurrentStatus.PENDING;
        } catch (YamlRateLimitingConfigException e) {
            error = e;
            errorMsg = e.getMessage();
        }

        long now = TimeUnit.NANOSECONDS.toMillis(NanoTimeSupplier.deNull(currentTimeSupplier).now());

        Current current = Current.builder().status(currentStatus).asOf(now).error(errorMsg).build();

        RateLimitingFactoriesSupplierWithStatus configurationWithStatus =
                RateLimitingFactoriesSupplierWithStatus.builder()
                        .supplier(InternalLimiterFactoriesSupplier.NOOP)
                        .status(RateLimiterStatus.builder()
                                .current(current)
                                .fromSource(sourcedFrom)
                                .build())
                        .build();
        ExtendedYamlConfigFileDTO yaml = dto == null ? null : dto.getRatelimit();

        return new InitialConfig( error, yaml, configurationWithStatus );
    }

    // packageFriendly for Testing
    static UaaYamlConfigFileDTO parseFile(BindYaml<UaaYamlConfigFileDTO> bindYaml, String fileText) {
        return bindYaml.bind(fileText);
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class ExtendedYamlConfigFileDTO extends YamlConfigFileDTO {
        private String dynamicConfigUrl;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    public static class UaaYamlConfigFileDTO {
        private ExtendedYamlConfigFileDTO ratelimit;

        @Override
        public String toString() {
            return UaaYamlUtils.dump(this);
        }
    }
}