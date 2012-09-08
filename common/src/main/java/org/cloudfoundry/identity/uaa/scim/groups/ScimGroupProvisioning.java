package org.cloudfoundry.identity.uaa.scim.groups;

import java.util.List;

public interface ScimGroupProvisioning {

    public List<ScimGroup> retrieveGroups();

    public List<ScimGroup> retrieveGroups(String filter);

    public List<ScimGroup> retrieveGroups(String filter, String sortBy, boolean ascending);

    public ScimGroup retrieveGroup(String id) throws GroupNotFoundException;

    public ScimGroup retrieveGroupByName(String name) throws GroupNotFoundException;

    public ScimGroup createGroup(ScimGroup group) throws InvalidGroupException;

    public ScimGroup updateGroup(String id, ScimGroup group) throws InvalidGroupException, GroupNotFoundException;

    public ScimGroup removeGroup(String id, int version) throws GroupNotFoundException;
}
