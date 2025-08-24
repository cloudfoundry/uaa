/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;
import org.cloudfoundry.identity.uaa.EntityWithAlias;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.StringUtils;

import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.util.Date;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UNKNOWN;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.getNodeAsBoolean;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.getNodeAsDate;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.getNodeAsInt;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.getNodeAsString;

@Getter
@JsonSerialize(using = IdentityProvider.IdentityProviderSerializer.class)
@JsonDeserialize(using = IdentityProvider.IdentityProviderDeserializer.class)
public class IdentityProvider<T extends AbstractIdentityProviderDefinition> implements EntityWithAlias {

    public static final String FIELD_ID = "id";
    public static final String FIELD_ORIGIN_KEY = "originKey";
    public static final String FIELD_NAME = "name";
    public static final String FIELD_VERSION = "version";
    public static final String FIELD_CREATED = "created";
    public static final String FIELD_LAST_MODIFIED = "last_modified";
    public static final String FIELD_ACTIVE = "active";
    public static final String FIELD_IDENTITY_ZONE_ID = "identityZoneId";
    public static final String FIELD_CONFIG = "config";
    public static final String FIELD_TYPE = "type";
    public static final String FIELD_ALIAS_ID = "aliasId";
    public static final String FIELD_ALIAS_ZID = "aliasZid";
    //see deserializer at the bottom

    private String id;
    @NotNull
    private String originKey;
    @NotNull
    private String name;
    @NotNull
    private String type;
    private T config;
    private int version;
    private Date created = new Date();
    @JsonProperty("last_modified")
    private Date lastModified = new Date();
    private boolean active = true;
    private String identityZoneId;
    private String aliasId;
    private String aliasZid;
    @JsonIgnore
    private boolean serializeConfigRaw;

    public IdentityProvider<T> setCreated(Date created) {
        this.created = created;
        return this;
    }

    public IdentityProvider<T> setLastModified(Date lastModified) {
        this.lastModified = lastModified;
        return this;
    }

    public IdentityProvider<T> setVersion(int version) {
        this.version = version;
        return this;
    }

    public IdentityProvider<T> setName(String name) {
        this.name = name;
        return this;
    }

    public IdentityProvider<T> setId(String id) {
        this.id = id;
        return this;
    }

    @Override
    public String getZoneId() {
        return getIdentityZoneId();
    }

    public IdentityProvider<T> setConfig(T config) {
        this.type = UNKNOWN;
        if (config != null) {
            this.type = determineType(config.getClass());
            if (SAML.equals(this.type)) {
                if (StringUtils.hasText(getOriginKey())) {
                    ((SamlIdentityProviderDefinition) config).setIdpEntityAlias(getOriginKey());
                }
                if (StringUtils.hasText(getIdentityZoneId())) {
                    ((SamlIdentityProviderDefinition) config).setZoneId(getIdentityZoneId());
                }
            }
        }
        this.config = config;
        return this;
    }

    private static String determineType(Class<? extends AbstractIdentityProviderDefinition> clazz) {
        if (SamlIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
            return SAML;
        } else if (UaaIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
            return UAA;
        } else if (RawExternalOAuthIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
            return OAUTH20;
        } else if (OIDCIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
            return OIDC10;
        } else if (LdapIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
            return LDAP;
        } else if (KeystoneIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
            return KEYSTONE;
        } else if (AbstractIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
            return UNKNOWN;
        } else {
            throw new IllegalArgumentException("Unknown identity provider configuration type:" + clazz.getName());
        }
    }

    public IdentityProvider<T> setOriginKey(String originKey) {
        this.originKey = originKey;
        if (config != null && config instanceof SamlIdentityProviderDefinition definition) {
            definition.setIdpEntityAlias(originKey);
        }

        return this;
    }

    public IdentityProvider<T> setType(String type) {
        this.type = type;
        return this;
    }

    public IdentityProvider<T> setActive(boolean active) {
        this.active = active;
        return this;
    }

    public IdentityProvider<T> setIdentityZoneId(String identityZoneId) {
        this.identityZoneId = identityZoneId;
        if (config != null && config instanceof SamlIdentityProviderDefinition definition) {
            definition.setZoneId(identityZoneId);
        }
        return this;
    }

    @Override
    public void setAliasId(String aliasId) {
        this.aliasId = aliasId;
    }

    @Override
    public void setAliasZid(String aliasZid) {
        this.aliasZid = aliasZid;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (config == null ? 0 : config.hashCode());
        result = prime * result + (created == null ? 0 : created.hashCode());
        result = prime * result + (id == null ? 0 : id.hashCode());
        result = prime * result + (lastModified == null ? 0 : lastModified.hashCode());
        result = prime * result + (name == null ? 0 : name.hashCode());
        result = prime * result + (originKey == null ? 0 : originKey.hashCode());
        result = prime * result + (type == null ? 0 : type.hashCode());
        result = prime * result + (aliasId == null ? 0 : aliasId.hashCode());
        result = prime * result + (aliasZid == null ? 0 : aliasZid.hashCode());
        result = prime * result + version;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        IdentityProvider other = (IdentityProvider) obj;
        if (config == null) {
            if (other.config != null) {
                return false;
            }
        } else if (!config.equals(other.config)) {
            return false;
        }
        if (created == null) {
            if (other.created != null) {
                return false;
            }
        } else if (!created.equals(other.created)) {
            return false;
        }
        if (id == null) {
            if (other.id != null) {
                return false;
            }
        } else if (!id.equals(other.id)) {
            return false;
        }
        if (lastModified == null) {
            if (other.lastModified != null) {
                return false;
            }
        } else if (!lastModified.equals(other.lastModified)) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (originKey == null) {
            if (other.originKey != null) {
                return false;
            }
        } else if (!originKey.equals(other.originKey)) {
            return false;
        }
        if (type == null) {
            if (other.type != null) {
                return false;
            }
        } else if (!type.equals(other.type)) {
            return false;
        }
        if (aliasId == null) {
            if (other.aliasId != null) {
                return false;
            }
        } else if (!aliasId.equals(other.aliasId)) {
            return false;
        }
        if (aliasZid == null) {
            if (other.aliasZid != null) {
                return false;
            }
        } else if (!aliasZid.equals(other.aliasZid)) {
            return false;
        }
        return version == other.version;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("IdentityProvider{");
        sb.append("id='").append(id).append('\'');

        sb.append(", identityZoneId=");
        if (identityZoneId != null) {
            sb.append('\'').append(identityZoneId).append('\'');
        } else {
            sb.append("null");
        }

        sb.append(", originKey='").append(originKey).append('\'');
        sb.append(", name='").append(name).append('\'');
        sb.append(", type='").append(type).append('\'');
        sb.append(", active=").append(active);

        sb.append(", aliasId=");
        if (aliasId != null) {
            sb.append('\'').append(aliasId).append('\'');
        } else {
            sb.append("null");
        }

        sb.append(", aliasZid=");
        if (aliasZid != null) {
            sb.append('\'').append(aliasZid).append('\'');
        } else {
            sb.append("null");
        }

        sb.append('}');
        return sb.toString();
    }

    @JsonIgnore
    public void setSerializeConfigRaw(boolean serializeConfigRaw) {
        this.serializeConfigRaw = serializeConfigRaw;
    }

    public static class IdentityProviderSerializer extends JsonSerializer<IdentityProvider> {
        @Override
        public void serialize(IdentityProvider value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeStartObject();
            gen.writeStringField(FIELD_TYPE, value.getType());

            if (value.isSerializeConfigRaw()) {
                gen.writeObjectField(FIELD_CONFIG, value.getConfig());
            } else {
                gen.writeStringField(FIELD_CONFIG, JsonUtils.writeValueAsString(value.getConfig()));
            }
            gen.writeStringField(FIELD_ID, value.getId());
            gen.writeStringField(FIELD_ORIGIN_KEY, value.getOriginKey());
            gen.writeStringField(FIELD_NAME, value.getName());
            gen.writeNumberField(FIELD_VERSION, value.getVersion());
            writeDateField(FIELD_CREATED, value.getCreated(), gen);
            writeDateField(FIELD_LAST_MODIFIED, value.getLastModified(), gen);
            gen.writeBooleanField(FIELD_ACTIVE, value.isActive());
            gen.writeStringField(FIELD_IDENTITY_ZONE_ID, value.getIdentityZoneId());
            gen.writeStringField(FIELD_ALIAS_ID, value.getAliasId());
            gen.writeStringField(FIELD_ALIAS_ZID, value.getAliasZid());
            gen.writeEndObject();
        }

        public void writeDateField(String fieldName, Date value, JsonGenerator gen) throws IOException {
            if (value != null) {
                gen.writeNumberField(fieldName, value.getTime());
            } else {
                gen.writeNullField(fieldName);
            }
        }
    }

    public static class IdentityProviderDeserializer extends JsonDeserializer<IdentityProvider> {
        @Override
        public IdentityProvider deserialize(JsonParser jp, DeserializationContext ctxt) {
            IdentityProvider result = new IdentityProvider();
            //determine the type of IdentityProvider
            JsonNode node = JsonUtils.readTree(jp);
            String type = getNodeAsString(node, FIELD_TYPE, UNKNOWN);
            //deserialize based on type
            String config;
            JsonNode configNode = node.get("config");
            if (configNode == null) {
                config = null;
            } else if (configNode.isTextual()) {
                config = configNode.textValue();
            } else {
                config = configNode.toString();
            }
            AbstractIdentityProviderDefinition definition = null;
            if (StringUtils.hasText(config)) {
                switch (type) {
                    case SAML:
                        definition = JsonUtils.readValue(config, SamlIdentityProviderDefinition.class);
                        break;
                    case OAUTH20:
                        definition = JsonUtils.readValue(config, RawExternalOAuthIdentityProviderDefinition.class);
                        break;
                    case OIDC10:
                        definition = JsonUtils.readValue(config, OIDCIdentityProviderDefinition.class);
                        break;
                    case UAA:
                        definition = JsonUtils.readValue(config, UaaIdentityProviderDefinition.class);
                        break;
                    case LDAP:
                        definition = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
                        break;
                    case KEYSTONE:
                        definition = JsonUtils.readValue(config, KeystoneIdentityProviderDefinition.class);
                        break;
                    default:
                        definition = JsonUtils.readValue(config, AbstractIdentityProviderDefinition.class);
                        break;
                }
            }
            result.setConfig(definition);
            result.setType(type);
            result.setId(getNodeAsString(node, FIELD_ID, null));
            result.setOriginKey(getNodeAsString(node, FIELD_ORIGIN_KEY, null));
            result.setName(getNodeAsString(node, FIELD_NAME, null));
            result.setVersion(getNodeAsInt(node, FIELD_VERSION, 0));
            result.setCreated(getNodeAsDate(node, FIELD_CREATED));
            result.setLastModified(getNodeAsDate(node, FIELD_LAST_MODIFIED));
            result.setActive(getNodeAsBoolean(node, FIELD_ACTIVE, true));
            result.setIdentityZoneId(getNodeAsString(node, FIELD_IDENTITY_ZONE_ID, null));
            result.setAliasId(getNodeAsString(node, FIELD_ALIAS_ID, null));
            result.setAliasZid(getNodeAsString(node, FIELD_ALIAS_ZID, null));
            return result;
        }
    }
}
