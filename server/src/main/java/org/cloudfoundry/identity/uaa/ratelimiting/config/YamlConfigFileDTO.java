package org.cloudfoundry.identity.uaa.ratelimiting.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.util.UaaYamlUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class YamlConfigFileDTO {
    @Getter
    @Setter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LimiterMap {
        private String name;
        private String global;
        private String withCallerCredentialsID;
        private String withCallerRemoteAddressID;
        private String withoutCallerID;
        private List<String> pathSelectors = new ArrayList<>();

        public boolean normalizeAndCheckEmpty() {
            name = StringUtils.stripToNull(name);
            global = StringUtils.stripToNull(global);
            withCallerCredentialsID = StringUtils.stripToNull(withCallerCredentialsID);
            withCallerRemoteAddressID = StringUtils.stripToNull(withCallerRemoteAddressID);
            withoutCallerID = StringUtils.stripToNull(withoutCallerID);
            pathSelectors = pathSelectors == null ? List.of() : pathSelectors.stream()
                    .map(StringUtils::stripToNull).filter(Objects::nonNull)
                    .toList();
            return (name == null) && (global == null)
                    && (withCallerCredentialsID == null) && (withCallerRemoteAddressID == null) && (withoutCallerID == null)
                    && pathSelectors.isEmpty();
        }

        @Override
        public String toString() {
            return UaaYamlUtils.dump(this);
        }
    }

    private String loggingOption;
    private String credentialID;
    private List<LimiterMap> limiterMappings = new ArrayList<>();

    @Override
    public String toString() {
        return UaaYamlUtils.dump(this);
    }
}
