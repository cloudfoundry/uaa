package org.cloudfoundry.identity.uaa.authentication;

import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component("samlResponseLoggerBinding")
public class SamlResponseLoggerBinding implements SAMLBinding {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlResponseLoggerBinding.class);

    public static final String X_VCAP_REQUEST_ID_HEADER = "X-Vcap-Request-Id";

    @Override
    public boolean supports(InTransport transport) {
        if (!(transport instanceof HttpServletRequestAdapter)) {
            return false;
        }

        HttpServletRequest httpServletRequest = ((HttpServletRequestAdapter) transport).getWrappedRequest();
        LOGGER.warn("Malformed SAML response. More details at log level DEBUG.");

        if (httpServletRequest == null) {
            LOGGER.debug("HttpServletRequest is null - no information to log");
            return false;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Method: {}, Params (name/size): {}, Content-type: {}, Request-size: {}, {}: {}",
                    httpServletRequest.getMethod(),
                    describeParameters(httpServletRequest),
                    httpServletRequest.getContentType(),
                    httpServletRequest.getContentLength(),
                    X_VCAP_REQUEST_ID_HEADER,
                    httpServletRequest.getHeader(X_VCAP_REQUEST_ID_HEADER));
        }
        return false;
    }

    private static String describeParameters(HttpServletRequest t) {
        if (t == null || t.getParameterMap() == null) {
            return null;
        }

        return t.getParameterMap()
                .entrySet()
                .stream()
                .map(SamlResponseLoggerBinding::formatParam)
                .collect(Collectors.joining(" "));
    }

    private static String formatParam(Map.Entry<String, String[]> p) {

        if (p == null) {
            return "(UNKNOWN/0)";
        }

        if (p.getValue() == null) {
            return String.format("(%s/0)", p.getKey());
        }

        List<String> formattedParams = new ArrayList<>(p.getValue().length);

        for (String val : p.getValue()) {
            formattedParams.add(String.format("(%s/%s)", p.getKey(), val == null ? 0 : val.length()));
        }

        return String.join(" ", formattedParams);
    }

    @Override
    public boolean supports(OutTransport transport) {
        return false;
    }

    @Override
    public MessageDecoder getMessageDecoder() {
        return null;
    }

    @Override
    public MessageEncoder getMessageEncoder() {
        return null;
    }

    @Override
    public String getBindingURI() {
        return "NON_NULL_BINDING_URI_UNUSED_SamlResponseLoggerBinding";
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

    }
}
