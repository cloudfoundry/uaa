/*******************************************************************************
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
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.StringUtils;

import javax.validation.constraints.NotNull;
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

@JsonSerialize(using = IdentityProvider.IdentityProviderSerializer.class)
@JsonDeserialize(using = IdentityProvider.IdentityProviderDeserializer.class)
public class IdentityProvider<T extends AbstractIdentityProviderDefinition> {

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
    //see deserializer at the bottom
    private String id;
    @NotNull
    private String originKey;
    @NotNull
    private String name;
    @NotNull
    private String type;
    private T config;
    private int version = 0;
    private Date created = new Date();
    @JsonProperty("last_modified")
    private Date lastModified = new Date();
    private boolean active = true;
    private String identityZoneId;

    public Date getCreated() {
        return created;
    }

    public IdentityProvider setCreated(Date created) {
        this.created = created;
        return this;
    }

    public Date getLastModified() {
        return lastModified;
    }

    public IdentityProvider setLastModified(Date lastModified) {
        this.lastModified = lastModified;
        return this;
    }

    public IdentityProvider setVersion(int version) {
        this.version = version;
        return this;
    }

    public int getVersion() {
        return version;
    }

    public String getName() {
        return name;
    }

    public IdentityProvider setName(String name) {
        this.name = name;
        return this;
    }

    public String getId() {
        return id;
    }

    public IdentityProvider setId(String id) {
        this.id = id;
        return this;
    }

    public T getConfig() {
        return config;
    }

    public IdentityProvider setConfig(T config) {
        if (config == null) {
            this.type = UNKNOWN;
        } else {
            Class clazz = config.getClass();
            if (SamlIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = SAML;
                if (StringUtils.hasText(getOriginKey())) {
                    ((SamlIdentityProviderDefinition) config).setIdpEntityAlias(getOriginKey());
                }
                if (StringUtils.hasText(getIdentityZoneId())) {
                    ((SamlIdentityProviderDefinition) config).setZoneId(getIdentityZoneId());
                }
            } else if (UaaIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = UAA;
            } else if (RawExternalOAuthIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = OAUTH20;
            } else if (OIDCIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = OIDC10;
            } else if (LdapIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = LDAP;
            } else if (KeystoneIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = KEYSTONE;
            } else if (AbstractIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = UNKNOWN;
            } else {
                throw new IllegalArgumentException("Unknown identity provider configuration type:" + clazz.getName());
            }
        }
        this.config = config;
        return this;
    }

    public String getOriginKey() {
        return originKey;
    }

    public IdentityProvider setOriginKey(String originKey) {
        this.originKey = originKey;
        if (config != null && config instanceof SamlIdentityProviderDefinition) {
            ((SamlIdentityProviderDefinition) config).setIdpEntityAlias(originKey);
        }

        return this;
    }

    public String getType() {
        return type;
    }

    public IdentityProvider setType(String type) {
        this.type = type;
        return this;
    }

    public boolean isActive() {
        return active;
    }

    public IdentityProvider setActive(boolean active) {
        this.active = active;
        return this;
    }

    public String getIdentityZoneId() {
        return identityZoneId;
    }

    public IdentityProvider setIdentityZoneId(String identityZoneId) {
        this.identityZoneId = identityZoneId;
        if (config != null && config instanceof SamlIdentityProviderDefinition) {
            ((SamlIdentityProviderDefinition) config).setZoneId(identityZoneId);
        }
        return this;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((config == null) ? 0 : config.hashCode());
        result = prime * result + ((created == null) ? 0 : created.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((lastModified == null) ? 0 : lastModified.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((originKey == null) ? 0 : originKey.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + version;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        IdentityProvider other = (IdentityProvider) obj;
        if (config == null) {
            if (other.config != null)
                return false;
        } else if (!config.equals(other.config))
            return false;
        if (created == null) {
            if (other.created != null)
                return false;
        } else if (!created.equals(other.created))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (lastModified == null) {
            if (other.lastModified != null)
                return false;
        } else if (!lastModified.equals(other.lastModified))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (originKey == null) {
            if (other.originKey != null)
                return false;
        } else if (!originKey.equals(other.originKey))
            return false;
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type))
            return false;
        if (version != other.version)
            return false;
        return true;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("IdentityProvider{");
        sb.append("id='").append(id).append('\'');
        sb.append(", originKey='").append(originKey).append('\'');
        sb.append(", name='").append(name).append('\'');
        sb.append(", type='").append(type).append('\'');
        sb.append(", active=").append(active);
        sb.append('}');
        return sb.toString();
    }

    private boolean serializeConfigRaw;

    @JsonIgnore
    public boolean isSerializeConfigRaw() {
        return serializeConfigRaw;
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
            return result;
        }


    }

}
