package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.springframework.core.MethodParameter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.mvc.method.annotation.RequestResponseBodyMethodProcessor;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
* Created by pivotal on 3/6/14.
*/
public class ScimEtagHandlerMethodReturnValueHandler extends RequestResponseBodyMethodProcessor {

    public ScimEtagHandlerMethodReturnValueHandler(List<HttpMessageConverter<?>> messageConverters) {
        super(messageConverters);
    }

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        return ScimCore.class.isAssignableFrom(returnType.getMethod().getReturnType());
    }

    @Override
    public void handleReturnValue(Object returnValue, MethodParameter returnType,
            ModelAndViewContainer mavContainer, NativeWebRequest webRequest) throws IOException,
            HttpMediaTypeNotAcceptableException {
        if (returnValue instanceof ScimCore) {
            HttpServletResponse response = webRequest.getNativeResponse(HttpServletResponse.class);
            response.addHeader("ETag", "\"" + ((ScimCore) returnValue).getVersion() + "\"");
        }
        super.handleReturnValue(returnValue, returnType, mavContainer, webRequest);
    }

}
