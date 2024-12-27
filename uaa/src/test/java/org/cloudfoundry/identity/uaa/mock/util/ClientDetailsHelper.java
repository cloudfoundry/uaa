package org.cloudfoundry.identity.uaa.mock.util;

import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

public class ClientDetailsHelper {
    public static Object fromString(String body, Class<?> clazz) {
        return JsonUtils.readValue(body, clazz);
    }

    public static ClientDetails[] clientArrayFromString(String clients) throws Exception {
        return (ClientDetails[]) arrayFromString(clients, ClientDetailsModification[].class);
    }

    public static Object[] arrayFromString(String body, Class<?> clazz) {
        return (Object[]) JsonUtils.readValue(body, clazz);
    }

    public static ClientDetails clientFromString(String client) throws Exception {
        return (ClientDetails) fromString(client, ClientDetailsModification.class);
    }
}
