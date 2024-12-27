package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.apache.commons.lang3.StringUtils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class YamlLoggingOption {
    private final String value;

    /**
     * Map a yaml LoggingOption (String) to <code>value</code> into a <code>YamlLoggingOption</code>.
     *
     * @return null if <code>yamlCredentialID</code> is null or blank.
     */
    public static YamlLoggingOption from(String yamlLoggingOption) {
        yamlLoggingOption = StringUtils.stripToNull(yamlLoggingOption);
        return yamlLoggingOption == null ? null : new YamlLoggingOption( yamlLoggingOption );
    }
}
