package org.cloudfoundry.identity.uaa.oauth.client.http.converter;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public final class FormOAuth2ExceptionHttpMessageConverter implements HttpMessageConverter<OAuth2Exception> {

    private static final List<MediaType> SUPPORTED_MEDIA = Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED);

    private final FormHttpMessageConverter delegateMessageConverter = new FormHttpMessageConverter();

    public boolean canRead(Class<?> clazz, MediaType mediaType) {
        return OAuth2Exception.class.equals(clazz) && MediaType.APPLICATION_FORM_URLENCODED.equals(mediaType);
    }

    public boolean canWrite(Class<?> clazz, MediaType mediaType) {
        return OAuth2Exception.class.equals(clazz) && MediaType.APPLICATION_FORM_URLENCODED.equals(mediaType);
    }

    public List<MediaType> getSupportedMediaTypes() {
        return SUPPORTED_MEDIA;
    }

    public OAuth2Exception read(Class<? extends OAuth2Exception> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        MultiValueMap<String, String> data = delegateMessageConverter.read(null, inputMessage);
        Map<String, String> flattenedData = data.toSingleValueMap();
        return OAuth2Exception.valueOf(flattenedData);
    }

    public void write(OAuth2Exception t, MediaType contentType, HttpOutputMessage outputMessage) throws IOException,
            HttpMessageNotWritableException {
        MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
        data.add(OAuth2Exception.ERROR, t.getOAuth2ErrorCode());
        data.add(OAuth2Exception.DESCRIPTION, t.getMessage());
        Map<String, String> additionalInformation = t.getAdditionalInformation();
        if (additionalInformation != null) {
            for (Map.Entry<String, String> entry : additionalInformation.entrySet()) {
                data.add(entry.getKey(), entry.getValue());
            }
        }
        delegateMessageConverter.write(data, contentType, outputMessage);
    }

}
