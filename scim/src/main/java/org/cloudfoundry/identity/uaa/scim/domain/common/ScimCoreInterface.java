package org.cloudfoundry.identity.uaa.scim.domain.common;

import org.codehaus.jackson.annotate.JsonIgnore;

public interface ScimCoreInterface
{
    
    public static final String[] SCHEMAS = new String[] { "urn:scim:schemas:core:1.0" };
    
    public abstract void setSchemas(String[] schemas);
    
    public abstract String getId();
    
    public abstract void setId(String id);
    
    public abstract String getExternalId();
    
    public abstract void setExternalId(String externalId);
    
    public abstract ScimMeta getMeta();
    
    public abstract void setMeta(ScimMeta meta);
    
    @JsonIgnore
    public abstract void setVersion(int version);
    
    @JsonIgnore
    public abstract int getVersion();
    
    public abstract String[] getSchemas();
    
}
