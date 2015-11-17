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
package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.config.LockoutPolicy;
import org.cloudfoundry.identity.uaa.config.PasswordPolicy;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.springframework.util.StringUtils;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.util.Date;

import static org.cloudfoundry.identity.uaa.authentication.Origin.KEYSTONE;
import static org.cloudfoundry.identity.uaa.authentication.Origin.LDAP;
import static org.cloudfoundry.identity.uaa.authentication.Origin.SAML;
import static org.cloudfoundry.identity.uaa.authentication.Origin.UAA;
import static org.cloudfoundry.identity.uaa.authentication.Origin.UNKNOWN;

@JsonDeserialize(using = IdentityProvider.IdentityProviderDeserializer.class)
public class IdentityProvider<T extends AbstractIdentityProviderDefinition> {

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
        if (config == null && this.type == null) {
            this.type = UNKNOWN;
        } else if (config !=null){
            Class clazz = config.getClass();
            if (SamlIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = SAML;
                if (StringUtils.hasText(getOriginKey())) {
                    ((SamlIdentityProviderDefinition)config).setIdpEntityAlias(getOriginKey());
                }
                if (StringUtils.hasText(getIdentityZoneId())) {
                    ((SamlIdentityProviderDefinition)config).setZoneId(getIdentityZoneId());
                }
            } else if (UaaIdentityProviderDefinition.class.isAssignableFrom(clazz)) {
                this.type = UAA;
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
        if (config!=null && config instanceof SamlIdentityProviderDefinition) {
            ((SamlIdentityProviderDefinition)config).setIdpEntityAlias(originKey);
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
        if (config!=null && config instanceof SamlIdentityProviderDefinition) {
            ((SamlIdentityProviderDefinition)config).setZoneId(identityZoneId);
        }
        return this;
    }

    public boolean configIsValid() {
        if (UAA.equals(originKey)) {
            UaaIdentityProviderDefinition configValue = ObjectUtils.castInstance(getConfig(), UaaIdentityProviderDefinition.class);
            if (configValue == null) {
                return true;
            }
            PasswordPolicy passwordPolicy = configValue.getPasswordPolicy();
            LockoutPolicy lockoutPolicy= configValue.getLockoutPolicy();

            if (passwordPolicy == null && lockoutPolicy == null) {
                return true;
            } else {
                boolean isValid = true;
                if(passwordPolicy != null) {
                    isValid = passwordPolicy.allPresentAndPositive();
                }
                if(lockoutPolicy != null) {
                    isValid = isValid && lockoutPolicy.allPresentAndPositive();
                }
                return isValid;
            }
        }
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
//        sb.append(", config='").append(config).append('\'');
//        sb.append(", version=").append(version);
//        sb.append(", created=").append(created);
//        sb.append(", lastModified=").append(lastModified);
//        sb.append(", identityZoneId='").append(identityZoneId).append('\'');
        sb.append('}');
        return sb.toString();
    }

    public static class IdentityProviderDeserializer extends JsonDeserializer<IdentityProvider> {
        @Override
        public IdentityProvider deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
            IdentityProvider result = new IdentityProvider();
            //determine the type of IdentityProvider
            JsonNode node = JsonUtils.readTree(jp);
            String type = getNodeAsString(node, "type", UNKNOWN);
            //deserialize based on type
            String config = getNodeAsJson(node, "config");
            AbstractIdentityProviderDefinition definition = null;
            if (StringUtils.hasText(config)) {
                switch (type) {
                    case SAML:
                        definition = JsonUtils.readValue(config, SamlIdentityProviderDefinition.class);
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

            result.setId(getNodeAsString(node,"id",null));
            result.setOriginKey(getNodeAsString(node,"originKey",null));
            result.setName(getNodeAsString(node,"name",null));
            result.setVersion(getNodeAsInt(node,"version",0));
            result.setCreated(getNodeAsDate(node,"created"));
            result.setLastModified(getNodeAsDate(node,"last_modified"));
            result.setActive(getNodeAsBoolean(node,"active",true));
            result.setIdentityZoneId(getNodeAsString(node,"identityZoneId",null));
            return result;
        }

        protected String getNodeAsJson(JsonNode node, String fieldName) {
            JsonNode typeNode = node.get(fieldName);
            return typeNode == null ? null : typeNode.toString();
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
            if (date==-1) {
                return null;
            } else {
                return new Date(date);
            }
        }

    }

}
