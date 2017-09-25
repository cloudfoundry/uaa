package org.cloudfoundry.identity.uaa.mfa_provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.StringUtils;

import javax.xml.bind.ValidationException;

import java.io.IOException;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.getNodeAsBoolean;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.getNodeAsString;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.readValue;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonDeserialize(using = MfaProvider.MfaProviderDeserializer.class)
public class MfaProvider<T extends AbstractMfaProviderConfig> {

    public static final String FIELD_TYPE = "type";
    public static final String FIELD_NAME = "name";
    public static final String FIELD_ACTIVE = "active";
    public static final String FIELD_ID = "id";



    private String id;
    private String name;
    private boolean active = true;
    private AbstractMfaProviderConfig config;
    private MfaProviderType type;

    enum MfaProviderType {
        GOOGLE_AUTHENTICATOR
    }

    public AbstractMfaProviderConfig getConfig() {
        return config;
    }

    public MfaProvider setConfig(T config) {
        this.config = config;
        return this;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Boolean getActive() {
        return active;
    }

    public MfaProvider setActive(boolean active) {
        this.active = active;
        return this;
    }

    public String getName() {
        return name;
    }

    public MfaProvider setName(String name) {
        this.name = name;
        return this;
    }

    public MfaProviderType getType() {
        return type;
    }

    public MfaProvider setType(MfaProviderType type) {
        this.type = type;
        return this;
    }

    public void validate() {
        if(StringUtils.isEmpty(name)) {
            throw new IllegalArgumentException("Provider name must be set");
        }
        if(name.length() > 255 || !name.matches("^[a-zA-Z0-9]*$")){
            throw new IllegalArgumentException("Provider name invalid");
        }
        if(type == null) {
            throw new IllegalArgumentException("Provider type must be set");
        }
        if(config == null) {
            throw new IllegalArgumentException("Provider config must be set");
        }
        config.validate();
    }

    public static class MfaProviderDeserializer extends JsonDeserializer<MfaProvider> {

        @Override
        public MfaProvider deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
            MfaProvider result =  new MfaProvider();

            JsonNode node = JsonUtils.readTree(p);
            MfaProviderType type;
            try {
                type = MfaProviderType.valueOf(getNodeAsString(node, FIELD_TYPE, MfaProviderType.GOOGLE_AUTHENTICATOR.name()));
            } catch(IllegalArgumentException e) {
                type = null;
            }
            //deserialize based on type
            JsonNode configNode = node.get("config");
            String config = configNode != null ? (configNode.isTextual() ? configNode.textValue() : configNode.toString()) : null;
            AbstractMfaProviderConfig definition = null;
            if(type != null) {
                switch(type) {
                    case GOOGLE_AUTHENTICATOR:
                        definition = StringUtils.hasText(config) ? JsonUtils.readValue(config, GoogleMfaProviderConfig.class) : null;
                        break;
                    default:
                        break;
                }
            }

            result.setConfig(definition);
            result.setType(type);
            result.setName(getNodeAsString(node, FIELD_NAME, null));
            result.setId(getNodeAsString(node, FIELD_ID, null));
            result.setActive(getNodeAsBoolean(node, FIELD_ACTIVE, true));




            return result;
        }
    }

}


