package org.cloudfoundry.identity.uaa.oauth.exceptions;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.Map.Entry;

public class OAuth2ExceptionJackson2Serializer extends StdSerializer<OAuth2Exception> {

    public OAuth2ExceptionJackson2Serializer() {
        super(OAuth2Exception.class);
    }

	@Override
	public void serialize(OAuth2Exception value, JsonGenerator jgen, SerializerProvider provider) throws IOException {
        jgen.writeStartObject();
		jgen.writeStringField("error", value.getOAuth2ErrorCode());
		jgen.writeStringField("error_description", value.getMessage());
		if (value.getAdditionalInformation()!=null) {
			for (Entry<String, String> entry : value.getAdditionalInformation().entrySet()) {
				String key = entry.getKey();
				String add = entry.getValue();
				jgen.writeStringField(key, add);				
			}
		}
        jgen.writeEndObject();
	}

}
