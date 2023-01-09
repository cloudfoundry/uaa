package org.cloudfoundry.identity.uaa.zone.model;

import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.ADMIN_CLIENT_CREDENTIALS_CANNOT_CONTAIN_SPACES_OR_BLANK;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.ADMIN_CLIENT_CREDENTIALS_VALIDATION_MESSAGE;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.ADMIN_CLIENT_CREDENTIALS_VALIDATION_PATTERN;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.UAA_CUSTOM_SUBDOMAIN_MESSAGE;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.UAA_CUSTOM_SUBDOMAIN_PATTERN;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.FieldDefaults;

@Getter
@FieldDefaults(makeFinal=true, level= AccessLevel.PRIVATE)
@ToString
@EqualsAndHashCode
@JsonInclude(Include.NON_NULL)
public class OrchestratorZone {

    @NotNull(message = ADMIN_CLIENT_CREDENTIALS_CANNOT_CONTAIN_SPACES_OR_BLANK)
    @Pattern(regexp = ADMIN_CLIENT_CREDENTIALS_VALIDATION_PATTERN,
             message= ADMIN_CLIENT_CREDENTIALS_VALIDATION_MESSAGE
    )
    private final String adminClientSecret;

    @Pattern(regexp = UAA_CUSTOM_SUBDOMAIN_PATTERN,
             message= UAA_CUSTOM_SUBDOMAIN_MESSAGE)
    private final String subdomain;

    @JsonCreator
    public OrchestratorZone(@JsonProperty("adminClientSecret") String adminClientSecret,
                            @JsonProperty("subdomain") String subdomain) {
        this.adminClientSecret = adminClientSecret;
        this.subdomain = subdomain;
    }
}
