/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import java.io.IOException;
import java.util.Date;

import javax.validation.constraints.NotNull;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = SamlServiceProvider.SamlServiceProviderSerializer.class)
@JsonDeserialize(using = SamlServiceProvider.SamlServiceProviderDeserializer.class)
public class SamlServiceProvider {

    public static final String FIELD_ID = "id";
    public static final String FIELD_ENTITY_ID = "entityId";
    public static final String FIELD_NAME = "name";
    public static final String FIELD_VERSION = "version";
    public static final String FIELD_CREATED = "created";
    public static final String FIELD_LAST_MODIFIED = "lastModified";
    public static final String FIELD_ACTIVE = "active";
    public static final String FIELD_IDENTITY_ZONE_ID = "identityZoneId";
    public static final String FIELD_CONFIG = "config";

    // see deserializer at the bottom
    private String id;
    @NotNull
    private String entityId;
    @NotNull
    private String name;
    private SamlServiceProviderDefinition config;
    private int version = 0;
    private Date created = new Date();
    private Date lastModified = new Date();
    private boolean active = true;
    private String identityZoneId;

    public Date getCreated() {
        return created;
    }

    public SamlServiceProvider setCreated(Date created) {
        this.created = created;
        return this;
    }

    public Date getLastModified() {
        return lastModified;
    }

    public SamlServiceProvider setLastModified(Date lastModified) {
        this.lastModified = lastModified;
        return this;
    }

    public SamlServiceProvider setVersion(int version) {
        this.version = version;
        return this;
    }

    public int getVersion() {
        return version;
    }

    public String getName() {
        return name;
    }

    public SamlServiceProvider setName(String name) {
        this.name = name;
        return this;
    }

    public String getId() {
        return id;
    }

    public SamlServiceProvider setId(String id) {
        this.id = id;
        return this;
    }

    public SamlServiceProviderDefinition getConfig() {
        return config;
    }

    public SamlServiceProvider setConfig(SamlServiceProviderDefinition config) {

        this.config = config;
        return this;
    }

    public String getEntityId() {
        return entityId;
    }

    public SamlServiceProvider setEntityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    public boolean isActive() {
        return active;
    }

    public SamlServiceProvider setActive(boolean active) {
        this.active = active;
        return this;
    }

    public String getIdentityZoneId() {
        return identityZoneId;
    }

    public SamlServiceProvider setIdentityZoneId(String identityZoneId) {
        this.identityZoneId = identityZoneId;
        return this;
    }

    public boolean configIsValid() {
        // There may be need for this method in the fugure but for now it does nothing.
        return true;
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
        result = prime * result + ((entityId == null) ? 0 : entityId.hashCode());
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
        SamlServiceProvider other = (SamlServiceProvider) obj;
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
        if (entityId == null) {
            if (other.entityId != null)
                return false;
        } else if (!entityId.equals(other.entityId))
            return false;
        if (version != other.version)
            return false;
        return true;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SamlServiceProvider{");
        sb.append("id='").append(id).append('\'');
        sb.append(", entityId='").append(entityId).append('\'');
        sb.append(", name='").append(name).append('\'');
        sb.append(", active=").append(active);
        sb.append('}');
        return sb.toString();
    }

    public static class SamlServiceProviderSerializer extends JsonSerializer<SamlServiceProvider> {
        @Override
        public void serialize(SamlServiceProvider value, JsonGenerator gen, SerializerProvider serializers)
                throws IOException {
            gen.writeStartObject();
            gen.writeStringField(FIELD_CONFIG, JsonUtils.writeValueAsString(value.getConfig()));
            gen.writeStringField(FIELD_ID, value.getId());
            gen.writeStringField(FIELD_ENTITY_ID, value.getEntityId());
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

    public static class SamlServiceProviderDeserializer extends JsonDeserializer<SamlServiceProvider> {
        @Override
        public SamlServiceProvider deserialize(JsonParser jp, DeserializationContext ctxt) {
            SamlServiceProvider result = new SamlServiceProvider();
            // determine the type of IdentityProvider
            JsonNode node = JsonUtils.readTree(jp);
            // deserialize based on type
            String config = getNodeAsString(node, FIELD_CONFIG, null);
            SamlServiceProviderDefinition definition = null;
            if (StringUtils.hasText(config)) {
                definition = JsonUtils.readValue(config, SamlServiceProviderDefinition.class);
            }
            result.setConfig(definition);

            result.setId(getNodeAsString(node, FIELD_ID, null));
            result.setEntityId(getNodeAsString(node, FIELD_ENTITY_ID, null));
            result.setName(getNodeAsString(node, FIELD_NAME, null));
            result.setVersion(getNodeAsInt(node, FIELD_VERSION, 0));
            result.setCreated(getNodeAsDate(node, FIELD_CREATED));
            result.setLastModified(getNodeAsDate(node, FIELD_LAST_MODIFIED));
            result.setActive(getNodeAsBoolean(node, FIELD_ACTIVE, true));
            result.setIdentityZoneId(getNodeAsString(node, FIELD_IDENTITY_ZONE_ID, null));
            return result;
        }

        protected String getNodeAsString(JsonNode node, String fieldName, String defaultValue) {
            JsonNode typeNode = node.get(fieldName);
            return typeNode == null ? defaultValue : typeNode.asText(defaultValue);
        }

        protected int getNodeAsInt(JsonNode node, String fieldName, int defaultValue) {
            JsonNode typeNode = node.get(fieldName);
            return typeNode == null ? defaultValue : typeNode.asInt(defaultValue);
        }

        protected boolean getNodeAsBoolean(JsonNode node, String fieldName, boolean defaultValue) {
            JsonNode typeNode = node.get(fieldName);
            return typeNode == null ? defaultValue : typeNode.asBoolean(defaultValue);
        }

        protected Date getNodeAsDate(JsonNode node, String fieldName) {
            JsonNode typeNode = node.get(fieldName);
            long date = typeNode == null ? -1 : typeNode.asLong(-1);
            if (date == -1) {
                return null;
            } else {
                return new Date(date);
            }
        }
    }

}
