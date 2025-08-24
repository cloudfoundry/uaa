package org.cloudfoundry.identity.uaa;

import org.springframework.http.HttpMethod;

public enum HttpMethodEnum {

    DELETE,
    GET,
    HEAD,
    OPTIONS,
    PATCH,
    POST,
    PUT,
    TRACE;

    public HttpMethod getHttpMethod() {
        return HttpMethod.valueOf(this.name());
    }
}
