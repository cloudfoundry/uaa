package org.cloudfoundry.identity.uaa.resources;

/**
 * Support table joins using a prefixed attribute mapping, e.g.
 * select * from table1 joinName join table2 joinName2 on joinName.origin = joinName2.origin_key ...
 * Used in SearchQueryConverter
 */
public class JoinAttributeNameMapper implements AttributeNameMapper {

    private final String name;
    private final String joinPrefix;
    private final int prefixLength;

    public JoinAttributeNameMapper(String name) {
        this.name = name;
        joinPrefix = name + ".";
        prefixLength = joinPrefix.length();
    }

    @Override
    public String mapToInternal(String attr) {
        return joinPrefix + attr;
    }

    @Override
    public String mapFromInternal(String attr) {
        return attr.substring(prefixLength);
    }

    public String getName() {
        return name;
    }
}
