package org.cloudfoundry.identity.uaa.util;

import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

public class UaaOAuth2Utils {

  public static final String CLIENT_ID = "client_id";
  public static final String STATE = "state";
  public static final String SCOPE = "scope";
  public static final String REDIRECT_URI = "redirect_uri";
  public static final String RESPONSE_TYPE = "response_type";
  public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";
  public static final String SCOPE_PREFIX = "scope.";
  public static final String GRANT_TYPE = "grant_type";

  public UaaOAuth2Utils() {
  }

  public static Set<String> parseParameterList(String values) {
    Set<String> result = new TreeSet();
    if (values != null && values.trim().length() > 0) {
      String[] tokens = values.split("[\\s+]");
      result.addAll(Arrays.asList(tokens));
    }

    return result;
  }

  public static String formatParameterList(Collection<String> value) {
    return value == null ? null : StringUtils.collectionToDelimitedString(value, " ");
  }

  public static Map<String, String> extractMap(String query) {
    Map<String, String> map = new HashMap();
    Properties properties = StringUtils.splitArrayElementsIntoProperties(StringUtils.delimitedListToStringArray(query, "&"), "=");
    if (properties != null) {
      Iterator var3 = properties.keySet().iterator();

      while(var3.hasNext()) {
        Object key = var3.next();
        map.put(key.toString(), properties.get(key).toString());
      }
    }

    return map;
  }

}
