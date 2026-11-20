package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.http.MockHttpOutputMessage;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;

class ExceptionReportHttpMessageConverterTest {

    private ExceptionReportHttpMessageConverter exceptionReportHttpMessageConverter;
    private HttpMessageConverter httpMessageConverter;
    private HttpOutputMessage httpOutputMessage;

    @BeforeEach
    void setUp() {
        exceptionReportHttpMessageConverter = new ExceptionReportHttpMessageConverter();

        httpMessageConverter = mock(HttpMessageConverter.class);
        httpOutputMessage = new MockHttpOutputMessage();
        exceptionReportHttpMessageConverter.setMessageConverters(
                new HttpMessageConverter<?>[]{httpMessageConverter});

        when(httpMessageConverter.canWrite(any(Class.class), any(MediaType.class))).thenReturn(true);
        when(httpMessageConverter.getSupportedMediaTypes()).thenReturn(Collections.singletonList(APPLICATION_JSON));
    }

    @Test
    void writeInternal() throws Exception {
        ExceptionReport report = new ExceptionReport(new Exception("oh noes!"));

        exceptionReportHttpMessageConverter.writeInternal(report, httpOutputMessage);

        Map<String, String> expectedFields = new HashMap<>();
        expectedFields.put("error", "exception");
        expectedFields.put("message", "oh noes!");
        expectedFields.put("error_description", "oh noes!");
        verify(httpMessageConverter).write(eq(expectedFields), eq(APPLICATION_JSON), eq(httpOutputMessage));
    }

    @Test
    void writeInteralWithExtraInfo() throws Exception {
        Map<String, Object> extraInfo = new HashMap<>();
        extraInfo.put("user_id", "cba09242-aa43-4247-9aa0-b5c75c281f94");
        extraInfo.put("active", true);
        extraInfo.put("verified", false);
        ExceptionReport report = new ExceptionReport(new Exception("oh noes!"), false, extraInfo);
        exceptionReportHttpMessageConverter.writeInternal(report, httpOutputMessage);

        Map<String, Object> expectedFields = new HashMap<>();
        expectedFields.put("error", "exception");
        expectedFields.put("message", "oh noes!");
        expectedFields.put("error_description", "oh noes!");
        expectedFields.putAll(extraInfo);
        verify(httpMessageConverter).write(eq(expectedFields), eq(APPLICATION_JSON), eq(httpOutputMessage));

    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"application/json", "application/problem+json"})
    void write_usesRequestedJsonContentType(String contentType) throws Exception {
        ExceptionReportHttpMessageConverter converter = new ExceptionReportHttpMessageConverter();
        MockHttpOutputMessage output = new MockHttpOutputMessage();
        MediaType mediaType = contentType == null ? null : MediaType.parseMediaType(contentType);

        converter.write(new ExceptionReport(new Exception("oh noes!")), mediaType, output);

        assertThat(output.getHeaders().getContentType())
                .isEqualTo(mediaType == null ? APPLICATION_JSON : mediaType);
        assertThat(JsonUtils.readValueAsMap(output.getBodyAsString()))
                .containsEntry("error", "exception")
                .containsEntry("message", "oh noes!")
                .containsEntry("error_description", "oh noes!");
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/json", "application/problem+json"})
    void read_usesRequestedJsonContentType(String contentType) throws Exception {
        ExceptionReportHttpMessageConverter converter = new ExceptionReportHttpMessageConverter();
        MockHttpInputMessage input = new MockHttpInputMessage(
                JsonUtils.writeValueAsBytes(Map.of("message", "oh noes!")));
        input.getHeaders().setContentType(MediaType.parseMediaType(contentType));

        ExceptionReport report = converter.read(ExceptionReport.class, input);

        assertThat(report.getException()).hasMessage("oh noes!");
    }

    @Test
    void supportedMediaTypes_excludeFormatsThatCannotSerializeMaps() {
        ExceptionReportHttpMessageConverter converter = new ExceptionReportHttpMessageConverter();

        assertThat(converter.canWrite(ExceptionReport.class, APPLICATION_JSON)).isTrue();
        assertThat(converter.canWrite(ExceptionReport.class, MediaType.TEXT_HTML)).isFalse();
        assertThat(converter.canWrite(ExceptionReport.class, MediaType.APPLICATION_OCTET_STREAM)).isFalse();
    }
}
