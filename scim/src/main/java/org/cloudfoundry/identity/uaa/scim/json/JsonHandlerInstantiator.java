package org.cloudfoundry.identity.uaa.scim.json;

import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.HandlerInstantiator;
import org.codehaus.jackson.map.JsonDeserializer;
import org.codehaus.jackson.map.JsonSerializer;
import org.codehaus.jackson.map.KeyDeserializer;
import org.codehaus.jackson.map.MapperConfig;
import org.codehaus.jackson.map.SerializationConfig;
import org.codehaus.jackson.map.introspect.Annotated;
import org.codehaus.jackson.map.jsontype.TypeIdResolver;
import org.codehaus.jackson.map.jsontype.TypeResolverBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

/**
 * When running within Spring, check to see if there is a bean
 * registered to handle the JSON deserialization.
 *
 * Extend this to convert @RequestBody parameters in the controllers
 * for ScimUserInterface and ScimGroupInterface to handle custom objects.
 */
public class JsonHandlerInstantiator extends HandlerInstantiator
{
    private ApplicationContext applicationContext;


    public JsonHandlerInstantiator()
    {
        super();
    }

    @Autowired
    public JsonHandlerInstantiator(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    /**
     * Retrieve Deserializer instance from Spring
     */
    @Override
    public JsonDeserializer<?> deserializerInstance(DeserializationConfig config, Annotated annotated,
            Class<? extends JsonDeserializer<?>> deserClass) {
        System.err.println("Looking for deserializer for " + deserClass);
        try {
            return (JsonDeserializer<?>) applicationContext.getBean(deserClass);
        } catch (Exception e) {
            // Return null and let the default behavior happen
        }
        return null;
    }

    @Override
    public KeyDeserializer keyDeserializerInstance(DeserializationConfig arg0, Annotated arg1,
            Class<? extends KeyDeserializer> arg2)
    {
        return null;
    }

    @Override
    public JsonSerializer<?> serializerInstance(SerializationConfig arg0, Annotated arg1,
            Class<? extends JsonSerializer<?>> arg2)
    {
        return null;
    }

    @Override
    public TypeIdResolver typeIdResolverInstance(MapperConfig<?> arg0, Annotated arg1,
            Class<? extends TypeIdResolver> arg2)
    {
        return null;
    }

    @Override
    public TypeResolverBuilder<?> typeResolverBuilderInstance(MapperConfig<?> arg0, Annotated arg1,
            Class<? extends TypeResolverBuilder<?>> arg2)
    {
        return null;
    }

}
