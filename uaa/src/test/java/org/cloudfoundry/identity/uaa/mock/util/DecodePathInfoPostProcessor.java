package org.cloudfoundry.identity.uaa.mock.util;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriUtils;
import org.springframework.web.util.WebUtils;

/**
 * Works around a bug in Spring Framework Mock MVC Tests
 * that double encodes %
 */

public class DecodePathInfoPostProcessor  implements RequestPostProcessor {

    private static Log logger = LogFactory.getLog(DecodePathInfoPostProcessor.class);

    @Override
    public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
        request.setPathInfo(decodeRequestString(request, request.getPathInfo()));
        return request;
    }


    /**
     * Performs URL decoding on the provided source using the encoding from the request.
     *
     * @param request the request to use to determine the encoding
     * @param source the source to URL encode
     * @return the URL encoded string
     */
    private String decodeRequestString(HttpServletRequest request, String source) {
        String enc = determineEncoding(request);
        try {
            return UriUtils.decode(source, enc);
        }
        catch (UnsupportedEncodingException ex) {
            if (logger.isWarnEnabled()) {
                logger.warn("Could not decode request string [" + source + "] with encoding '" + enc +
                                "': falling back to platform default encoding; exception message: " + ex.getMessage());
            }
            return URLDecoder.decode(source);
        }
    }

    /**
     * Determine the encoding for the given request.
     * Can be overridden in subclasses.
     * <p>The default implementation checks the request encoding,
     * falling back to {@code WebUtils.DEFAULT_CHARACTER_ENCODING}
     * @param request current HTTP request
     * @return the encoding for the request (never {@code null})
     * @see javax.servlet.ServletRequest#getCharacterEncoding()
     */
    private String determineEncoding(HttpServletRequest request) {
        String enc = request.getCharacterEncoding();
        if (enc == null) {
            enc = WebUtils.DEFAULT_CHARACTER_ENCODING;
        }
        return enc;
    }
}
