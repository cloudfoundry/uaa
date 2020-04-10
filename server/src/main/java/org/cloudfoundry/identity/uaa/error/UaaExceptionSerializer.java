
package org.cloudfoundry.identity.uaa.error;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.util.Map.Entry;

/**
 * @author Dave Syer
 *
 */
public class UaaExceptionSerializer extends JsonSerializer<UaaException> {

    @Override
    public void serialize(UaaException value, JsonGenerator jgen, SerializerProvider provider) throws IOException,
        JsonProcessingException {
        jgen.writeStartObject();
        jgen.writeStringField("error", value.getErrorCode());
        jgen.writeStringField("error_description", value.getMessage());
        if (value.getAdditionalInformation() != null) {
            for (Entry<String, String> entry : value.getAdditionalInformation().entrySet()) {
                String key = entry.getKey();
                String add = entry.getValue();
                jgen.writeStringField(key, add);
            }
        }
        jgen.writeEndObject();
    }

}
