package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class MtlsConfig {
    /** Zones opt in; the deployment's master switch must also be enabled. */
    @JsonSetter(nulls = Nulls.FAIL)
    private boolean enabled = false;

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private Map<String, String> trustBundles = new LinkedHashMap<>();
}
