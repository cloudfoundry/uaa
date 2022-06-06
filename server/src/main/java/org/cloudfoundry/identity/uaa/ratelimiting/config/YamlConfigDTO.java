package org.cloudfoundry.identity.uaa.ratelimiting.config;

import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.TypeProperties;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtils;

@NoArgsConstructor
@Getter
@Setter
@ToString
public class YamlConfigDTO {
    public static final String NO_NAME_PROVIDED = "Incomplete Rate Limiting configuration entry - No 'name' provided; in: ";

    private String loggingOption;
    private String credentialID;
    private String name;
    private String global;
    private String withCallerCredentialsID;
    private String withCallerRemoteAddressID;
    private String withoutCallerID;
    private List<String> pathSelectors = new ArrayList<>();

    public YamlLoggingOption toLoggingOption() {
        return YamlLoggingOption.from( loggingOption );
    }

    public YamlCredentialIdDefinition toCredentialIdDefinition() {
        return YamlCredentialIdDefinition.from( credentialID );
    }

    public TypeProperties toTypeProperties() {
        this.name = StringUtils.normalizeToNull( name );
        if ( (name == null) && (global == null)
             && (withCallerCredentialsID == null) && (withCallerRemoteAddressID == null) && (withoutCallerID == null)
             && pathSelectors.isEmpty() ) {
            return null;
        }
        if ( name == null ) {
            throw new RateLimitingConfigException( NO_NAME_PROVIDED + this );
        }
        return TypeProperties.builder()
                .name( name )
                .global( global )
                .withCallerCredentialsID( withCallerCredentialsID )
                .withCallerRemoteAddressID( withCallerRemoteAddressID )
                .withoutCallerID( withoutCallerID )
                .pathSelectors( pathSelectors )
                .build();
    }
}
