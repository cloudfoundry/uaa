package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;
import org.yaml.snakeyaml.Yaml;

@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
public class YamlConfigFileDTO {
    @Getter
    @Setter
    @ToString
    @NoArgsConstructor
    @EqualsAndHashCode
    public static class LimiterMap {
        private String name;
        private String global;
        private String withCallerCredentialsID;
        private String withCallerRemoteAddressID;
        private String withoutCallerID;
        private List<String> pathSelectors = new ArrayList<>();

        public boolean normalizeAndCheckEmpty() {
            name = StringUtils.normalizeToNull( name );
            global = StringUtils.normalizeToNull( global );
            withCallerCredentialsID = StringUtils.normalizeToNull( withCallerCredentialsID );
            withCallerRemoteAddressID = StringUtils.normalizeToNull( withCallerRemoteAddressID );
            withoutCallerID = StringUtils.normalizeToNull( withoutCallerID );
            pathSelectors = (pathSelectors == null) ? List.of() : pathSelectors.stream()
                    .map( StringUtils::normalizeToNull ).filter( Objects::nonNull )
                    .collect( Collectors.toList() );
            return (name == null) && (global == null)
                   && (withCallerCredentialsID == null) && (withCallerRemoteAddressID == null) && (withoutCallerID == null)
                   && pathSelectors.isEmpty();
        }
    }

    private String loggingOption;
    private String credentialID;
    private List<LimiterMap> limiterMappings = new ArrayList<>();

    @Override
    public String toString() {
        return new Yaml().dump( this );
    }
}
