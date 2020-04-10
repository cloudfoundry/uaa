package org.cloudfoundry.identity.uaa.provider;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ExternalIdentityProviderDefinition extends AbstractIdentityProviderDefinition {

  public static final String GROUP_ATTRIBUTE_NAME =
      "external_groups"; // can be a string or a list of strings
  public static final String EMAIL_ATTRIBUTE_NAME = "email"; // can be a string
  public static final String GIVEN_NAME_ATTRIBUTE_NAME = "given_name"; // can be a string
  public static final String FAMILY_NAME_ATTRIBUTE_NAME = "family_name"; // can be a string
  public static final String PHONE_NUMBER_ATTRIBUTE_NAME = "phone_number"; // can be a string
  public static final String EMAIL_VERIFIED_ATTRIBUTE_NAME = "email_verified"; // can be a string
  public static final String USER_ATTRIBUTE_PREFIX = "user.attribute.";
  public static final String USER_NAME_ATTRIBUTE_NAME = "user_name";

  public static final String STORE_CUSTOM_ATTRIBUTES_NAME = "storeCustomAttributes";

  public static final String EXTERNAL_GROUPS_WHITELIST = "externalGroupsWhitelist";
  public static final String ATTRIBUTE_MAPPINGS = "attributeMappings";

  private List<String> externalGroupsWhitelist = new LinkedList<>();
  private Map<String, Object> attributeMappings = new HashMap<>();
  private boolean addShadowUserOnLogin = true;
  private boolean storeCustomAttributes = true;

  public List<String> getExternalGroupsWhitelist() {
    return Collections.unmodifiableList(externalGroupsWhitelist);
  }

  public void setExternalGroupsWhitelist(List<String> externalGroupsWhitelist) {
    this.externalGroupsWhitelist =
        new LinkedList<>(externalGroupsWhitelist != null ? externalGroupsWhitelist : emptyList());
  }

  @JsonIgnore
  public void addWhiteListedGroup(String group) {
    this.externalGroupsWhitelist.add(group);
  }

  public Map<String, Object> getAttributeMappings() {
    return Collections.unmodifiableMap(attributeMappings);
  }

  public void setAttributeMappings(Map<String, Object> attributeMappings) {
    this.attributeMappings =
        new HashMap<>(attributeMappings != null ? attributeMappings : emptyMap());
  }

  /**
   * adds an attribute mapping, where the key is known to the UAA and the value represents the
   * attribute name on the IDP.
   *
   * @param key - known to the UAA, such as {@link #EMAIL_ATTRIBUTE_NAME}, {@link
   * #GROUP_ATTRIBUTE_NAME}, {@link #PHONE_NUMBER_ATTRIBUTE_NAME}
   * @param value - the name of the attribute on the IDP side, for example
   * <code>emailAddress</code>
   */
  @JsonIgnore
  public void addAttributeMapping(String key, Object value) {
    attributeMappings.put(key, value);
  }

  public boolean isAddShadowUserOnLogin() {
    return addShadowUserOnLogin;
  }

  public void setAddShadowUserOnLogin(boolean addShadowUserOnLogin) {
    this.addShadowUserOnLogin = addShadowUserOnLogin;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }

    ExternalIdentityProviderDefinition that = (ExternalIdentityProviderDefinition) o;

    if (addShadowUserOnLogin != that.addShadowUserOnLogin) {
      return false;
    }
    if (this.isStoreCustomAttributes() != that.isStoreCustomAttributes()) {
      return false;
    }
    if (getExternalGroupsWhitelist() != null
        ? !getExternalGroupsWhitelist().equals(that.getExternalGroupsWhitelist())
        : that.getExternalGroupsWhitelist() != null) {
      return false;
    }
    return Objects.equals(attributeMappings, that.attributeMappings);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result =
        31 * result + (externalGroupsWhitelist != null ? externalGroupsWhitelist.hashCode() : 0);
    result = 31 * result + (attributeMappings != null ? attributeMappings.hashCode() : 0);
    result = 31 * result + (addShadowUserOnLogin ? 1 : 0);
    return result;
  }

  public boolean isStoreCustomAttributes() {
    return storeCustomAttributes;
  }

  public void setStoreCustomAttributes(boolean storeCustomAttributes) {
    this.storeCustomAttributes = storeCustomAttributes;
  }
}
