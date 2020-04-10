package org.cloudfoundry.identity.uaa.scim;

import static java.util.Optional.ofNullable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScimGroup extends ScimCore<ScimGroup> {

  private String displayName;
  private String zoneId;
  private String description;

  private List<ScimGroupMember> members;

  public ScimGroup() {
    this(null);
  }

  public ScimGroup(String name) {
    this(null, name, null);
  }

  public ScimGroup(String id, String displayName, String zoneId) {
    super(id);
    this.displayName = displayName;
    this.zoneId = zoneId;
  }

  public String getDisplayName() {
    return displayName;
  }

  public ScimGroup setDisplayName(String displayName) {
    this.displayName = displayName;
    return this;
  }

  public String getZoneId() {
    return zoneId;
  }

  public ScimGroup setZoneId(String zoneId) {
    this.zoneId = zoneId;
    return this;
  }

  public List<ScimGroupMember> getMembers() {
    return members;
  }

  public ScimGroup setMembers(List<ScimGroupMember> members) {
    this.members = members;
    return this;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  @Override
  public void patch(ScimGroup patch) {
    String[] attributes = ofNullable(patch.getMeta().getAttributes()).orElse(new String[0]);
    for (String attribute : attributes) {
      switch (attribute.toUpperCase()) {
        case "DESCRIPTION":
          setDescription(null);
          break;
        case "DISPLAYNAME":
          setDisplayName(null);
          break;
        case "ZONEID":
          throw new IllegalArgumentException("Cannot delete or change ZoneId");
        case "ID":
          throw new IllegalArgumentException("Cannot delete or change ID");
        case "MEMBERS":
          setMembers(new ArrayList<>());
          break;
        default:
          throw new IllegalArgumentException(
              String.format("Attribute %s cannot be removed using \"Meta.attributes\"", attribute));
      }
    }

    if (patch.getMembers() != null) {
      // remove all members that are in the patch list
      Set<String> patchMemberIds =
          patch.getMembers().stream().map(ScimGroupMember::getMemberId).collect(Collectors.toSet());
      List<ScimGroupMember> newMembers = new ArrayList<>(getMembers());
      newMembers.removeIf(member -> patchMemberIds.contains(member.getMemberId()));

      // add back all members that don't have "delete" as operation
      newMembers.addAll(
          patch.getMembers().stream()
              .filter(member -> !("delete".equalsIgnoreCase(member.getOperation())))
              .collect(Collectors.toList()));

      setMembers(newMembers);
    }
    ofNullable(patch.getDescription()).ifPresent(this::setDescription);
    ofNullable(patch.getDisplayName()).ifPresent(this::setDisplayName);
  }

  @Override
  public String toString() {
    return String.format(
        "(Group id: %s, name: %s, description: %s, "
            + "created: %s, modified: %s, version: %s, members: %s)",
        getId(),
        displayName,
        description,
        getMeta().getCreated(),
        getMeta().getLastModified(),
        getVersion(),
        members);
  }
}
