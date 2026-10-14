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
    /** The deployment's master switch must also be enabled. */
    @JsonSetter(nulls = Nulls.FAIL)
    private boolean enabled = true;

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private Map<String, String> trustBundles = new LinkedHashMap<>();
}
