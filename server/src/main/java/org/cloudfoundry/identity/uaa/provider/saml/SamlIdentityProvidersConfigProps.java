
package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@Data
@ConfigurationProperties(prefix="login.saml")
public class SamlIdentityProvidersConfigProps {
    private Map<String, Map<String,Object>> providers;
}
