package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.login.AutologinRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AutologinRequestConverterTest {

    private final List<String> jsonMediaType = List.of(MediaType.APPLICATION_JSON_VALUE);
    private final List<String> htmlMediaType = List.of(MediaType.APPLICATION_XHTML_XML_VALUE);

    private AutologinRequest autologinRequest;

    private AutologinRequestConverter autologinRequestConverter;

    private HttpInputMessage inputMessage;

    private HttpHeaders httpHeaders;

    @BeforeEach
    void setUp() {
        autologinRequest = new AutologinRequest();
        autologinRequestConverter = new AutologinRequestConverter();
        inputMessage = mock(HttpInputMessage.class);
        httpHeaders = mock(HttpHeaders.class);
        when(inputMessage.getHeaders()).thenReturn(httpHeaders);
    }

    @Test
    void supports() {
        Object newObject = new Object();
        assertThat(autologinRequestConverter.supports(newObject.getClass())).isFalse();
        assertThat(autologinRequestConverter.supports(autologinRequest.getClass())).isTrue();
    }

    @Test
    void isJsonContent() {
        assertThat(autologinRequestConverter.isJsonContent(jsonMediaType)).isTrue();
        assertThat(autologinRequestConverter.isJsonContent(htmlMediaType)).isFalse();
    }

    @Test
    void readInternalNoJson() throws IOException {
        AutologinRequest autologin = autologinRequestConverter.readInternal(autologinRequest.getClass(), inputMessage);
        assertThat(autologin).isNotNull();
    }

    @Test
    void readInternalFromJson() throws IOException {
        InputStream inputStream = new ByteArrayInputStream("{ \"username\": \"user\",\"password\": \"pwd\" }".getBytes(StandardCharsets.UTF_8));
        when(httpHeaders.get(HttpHeaders.CONTENT_TYPE)).thenReturn(jsonMediaType);
        when(inputMessage.getBody()).thenReturn(inputStream);
        AutologinRequest autologin = autologinRequestConverter.readInternal(autologinRequest.getClass(), inputMessage);
        assertThat(autologin).isNotNull();
        assertThat(autologin.getUsername()).isEqualTo("user");
        assertThat(autologin.getPassword()).isEqualTo("pwd");
    }

    @Test
    void readInternalFromJsonButNull() throws IOException {
        when(httpHeaders.get(HttpHeaders.CONTENT_TYPE)).thenReturn(jsonMediaType);
        when(inputMessage.getBody()).thenReturn(null);
        AutologinRequest autologin = autologinRequestConverter.readInternal(autologinRequest.getClass(), inputMessage);
        assertThat(autologin).isNotNull();
        assertThat(autologin.getUsername()).isNull();
        assertThat(autologin.getPassword()).isNull();
    }

    @Test
    void writeInternal() throws IOException {
        OutputStream outputStream = mock(OutputStream.class);
        HttpOutputMessage outputMessage = mock(HttpOutputMessage.class);
        when(outputMessage.getHeaders()).thenReturn(httpHeaders);
        when(outputMessage.getBody()).thenReturn(outputStream);
        autologinRequest.setPassword("pwd");
        autologinRequest.setUsername("user");
        autologinRequestConverter.writeInternal(autologinRequest, outputMessage);
        verify(outputMessage, times(2)).getHeaders();
        verify(outputMessage, times(1)).getBody();
    }

    @Test
    void writeInternalNoValuesInAutoLoginRequest() throws IOException {
        OutputStream outputStream = mock(OutputStream.class);
        HttpOutputMessage outputMessage = mock(HttpOutputMessage.class);
        when(outputMessage.getHeaders()).thenReturn(httpHeaders);
        when(outputMessage.getBody()).thenReturn(outputStream);
        autologinRequestConverter.writeInternal(autologinRequest, outputMessage);
        verify(outputMessage, times(2)).getHeaders();
        verify(outputMessage, times(1)).getBody();
    }
}