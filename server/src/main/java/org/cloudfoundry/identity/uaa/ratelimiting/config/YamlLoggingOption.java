package org.cloudfoundry.identity.uaa.ratelimiting.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

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
    public static YamlLoggingOption from( String yamlLoggingOption ) {
        yamlLoggingOption = StringUtils.normalizeToNull( yamlLoggingOption );
        return (yamlLoggingOption == null) ? null : new YamlLoggingOption( yamlLoggingOption );
    }
}
