package org.cloudfoundry.identity.uaa.oauth.client.http.converter;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.util.MultiValueMap;

import java.io.IOException;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class FormOAuth2AccessTokenMessageConverter extends AbstractHttpMessageConverter<OAuth2AccessToken> {

    private final FormHttpMessageConverter delegateMessageConverter;

    public FormOAuth2AccessTokenMessageConverter() {
        super(MediaType.APPLICATION_FORM_URLENCODED, MediaType.TEXT_PLAIN);
        this.delegateMessageConverter = new FormHttpMessageConverter();
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return OAuth2AccessToken.class.equals(clazz);
    }

    @Override
    protected OAuth2AccessToken readInternal(Class<? extends OAuth2AccessToken> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        MultiValueMap<String, String> data = delegateMessageConverter.read(null, inputMessage);
        return DefaultOAuth2AccessToken.valueOf(data.toSingleValueMap());
    }

    @Override
    protected void writeInternal(OAuth2AccessToken accessToken, HttpOutputMessage outputMessage) throws IOException,
            HttpMessageNotWritableException {
        throw new UnsupportedOperationException(
                "This converter is only used for converting from externally aqcuired form data");
    }
}
