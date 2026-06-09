package org.cloudfoundry.identity.uaa.resources.jdbc;

import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.exceptions.ScimException;
import com.unboundid.scim2.common.filters.Filter;
import tools.jackson.databind.node.ValueNode;
import org.cloudfoundry.identity.uaa.resources.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.JoinAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter.ProcessedFilter.ORDER_BY;
import static org.springframework.util.StringUtils.hasText;

public class SimpleSearchQueryConverter implements SearchQueryConverter {

    private static final int MAX_FILTER_DEPTH = 20;

    //LOWER
    private static final List<String> VALID_ATTRIBUTE_NAMES = List.of(
            "id",
            "created",
            "lastmodified",
            "version",
            "username",
            "password",
            "email",
            "givenname",
            "familyname",
            "name.familyname",
            "name.givenname",
            "active",
            "phonenumber",
            "verified",
            "origin",
            "identity_zone_id",
            "passwd_lastmodified",
            "passwd_change_required",
            "last_logon_success_time",
            "previous_logon_success_time",
            "displayname",
            "scope",
            "group_id",
            "member_id",
            "member_type",
            "description",
            "client_id",
            "authorized_grant_types",
            "web_server_redirect_uri",
            "redirect_uri",
            "access_token_validity",
            "refresh_token_validity",
            "autoapprove",
            "show_on_home_page",
            "created_by",
            "required_user_groups",
            "user_id",
            "meta.lastmodified",
            "meta.created",
            "meta.location",
            "meta.resourcetype",
            "meta.version",
            "emails.value",
            "groups.display",
            "phonenumbers.value",
            "gm.external_group",
            "gm.origin",
            "g.displayname",
            "g.id",
            "external_id");

    private static final Logger logger = LoggerFactory.getLogger(SimpleSearchQueryConverter.class);
    private AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.emptyMap());

    private boolean dbCaseInsensitive;
    private final AlphanumericRandomValueStringGenerator randomStringGenerator;

    public SimpleSearchQueryConverter() {
        randomStringGenerator = new AlphanumericRandomValueStringGenerator();
    }

    private boolean isDbCaseInsensitive() {
        return dbCaseInsensitive;
    }

    public void setDbCaseInsensitive(boolean caseInsensitive) {
        this.dbCaseInsensitive = caseInsensitive;
    }

    public void setAttributeNameMapper(AttributeNameMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public ProcessedFilter convert(String filter, String sortBy, boolean ascending, String zoneId) {
        String paramPrefix = generateParameterPrefix(filter);
        Map<String, Object> values = new HashMap<>();
        String where = getWhereClause(filter, sortBy, ascending, values, mapper, paramPrefix, zoneId);
        ProcessedFilter pf = new ProcessedFilter(where, values, hasText(sortBy));
        pf.setParamPrefix(paramPrefix);
        return pf;
    }

    private String generateParameterPrefix(String filter) {
        while (true) {
            String s = randomStringGenerator.generate().toLowerCase();
            if (!filter.contains(s)) {
                return "__" + s + "_";
            }
        }
    }

    /**
     * @return the WHERE and (optional) ORDER BY clauses WITHOUT the "WHERE" keyword in the beginning
     */
    private String getWhereClause(
            @Nullable final String filter,
            @Nullable final String sortBy,
            final boolean ascending,
            final Map<String, Object> values,
            final AttributeNameMapper mapper,
            final String paramPrefix,
            final String zoneId) {

        try {
            final Filter zoneIdFilter = Filter.eq("identity_zone_id", zoneId);
            Filter fullFilter;
            if (hasText(filter)) {
                fullFilter = Filter.and(asList(scimFilter(filter), zoneIdFilter));
            } else {
                fullFilter = zoneIdFilter;
            }

            String whereClause = whereClauseFromFilter(fullFilter, values, mapper, paramPrefix);
            if (sortBy != null) {
                final String internalSortBy = mapper.mapToInternal(sortBy);
                // Need to add "asc" or "desc" explicitly to ensure that the pattern
                // splitting below works
                whereClause += ORDER_BY + internalSortBy + (ascending ? " ASC" : " DESC");
            }

            return whereClause;
        } catch (ScimException e) {
            logger.debug("Unable to parse {}", filter, e);
            throw new IllegalArgumentException("Invalid SCIM Filter: " + filter + "; Message: " + e.getMessage());
        }
    }

    @Override
    public MultiValueMap<String, Object> getFilterValues(String filter, List<String> validAttributes) throws IllegalArgumentException {
        try {
            Filter scimFilter = Filter.fromString(filter);
            validateFilterAttributes(scimFilter, validAttributes);
            MultiValueMap<String, Object> result = new LinkedMultiValueMap<>();
            extractValues(scimFilter, result);
            return result;
        } catch (ScimException x) {
            throw new IllegalArgumentException(x.getMessage());
        }
    }

    private Filter scimFilter(String filter) throws ScimException {
        Filter scimFilter;
        try {
            scimFilter = Filter.fromString(filter);
        } catch (ScimException e) {
            logger.debug("Attempting legacy scim filter conversion for [{}]", filter, e);
            filter = filter.replace("'", "\"");
            scimFilter = Filter.fromString(filter);
        }
        validateFilterAttributes(scimFilter, VALID_ATTRIBUTE_NAMES);
        return scimFilter;
    }

    private void validateFilterAttributes(Filter filter, List<String> validAttributeNames) throws ScimException {
        List<String> invalidAttributes = new LinkedList<>();
        validateFilterAttributes(filter, invalidAttributes, validAttributeNames, 0);
        if (!invalidAttributes.isEmpty()) {
            throw new BadRequestException("Invalid filter attributes:" + StringUtils.collectionToCommaDelimitedString(invalidAttributes));
        }
    }

    private void validateFilterAttributes(Filter filter, List<String> invalidAttribues, List<String> validAttributeNames, int depth) {
        if (depth > MAX_FILTER_DEPTH) {
            throw new IllegalArgumentException("Filter too deeply nested");
        }
        if (filter.getAttributePath() != null) {
            String name = filter.getAttributePath().toString();
            if (!validAttributeNames.contains(name.toLowerCase())) {
                invalidAttribues.add(name);
            }
        }
        for (Filter subfilter : ofNullable(filter.getCombinedFilters()).orElse(emptyList())) {
            validateFilterAttributes(subfilter, invalidAttribues, validAttributeNames, depth + 1);
        }
    }

    private void extractValues(Filter filter, MultiValueMap<String, Object> values) throws ScimException {
        extractValues(filter, values, 0);
    }

    private void extractValues(Filter filter, MultiValueMap<String, Object> values, int depth) throws ScimException {
        if (depth > MAX_FILTER_DEPTH) {
            throw new BadRequestException("Filter too deeply nested");
        }
        switch (filter.getFilterType()) {
            case AND:
                for (Filter component : filter.getCombinedFilters()) {
                    extractValues(component, values, depth + 1);
                }
                break;
            case OR:
                throw new BadRequestException("[or] operator is not supported.");
            case EQUAL:
                Object value = getStringOrDate(filter.getComparisonValue().asString());
                String key = filter.getAttributePath().toString();
                values.add(key, value);
                break;
            case CONTAINS:
                throw new BadRequestException("[co] operator is not supported.");
            case STARTS_WITH:
                throw new BadRequestException("[sw] operator is not supported.");
            case PRESENT:
                throw new BadRequestException("[pr] operator is not supported.");
            case GREATER_THAN:
                throw new BadRequestException("[gt] operator is not supported.");
            case GREATER_OR_EQUAL:
                throw new BadRequestException("[ge] operator is not supported.");
            case LESS_THAN:
                throw new BadRequestException("[lt] operator is not supported.");
            case LESS_OR_EQUAL:
                throw new BadRequestException("[le] operator is not supported.");
            default:
                throw new BadRequestException("Unknown filter operator:" + filter.getFilterType());
        }
    }

    private String buildCombiningClause(Filter filter, String operator, Map<String, Object> values, AttributeNameMapper mapper, String paramPrefix, int depth) {
        StringBuilder sb = new StringBuilder("(");
        List<Filter> components = filter.getCombinedFilters();
        sb.append(whereClauseFromFilter(components.getFirst(), values, mapper, paramPrefix, depth + 1));
        for (int i = 1; i < components.size(); i++) {
            sb.append(operator).append(whereClauseFromFilter(components.get(i), values, mapper, paramPrefix, depth + 1));
        }
        sb.append(")");
        return sb.toString();
    }

    private String whereClauseFromFilter(Filter filter, Map<String, Object> values, AttributeNameMapper mapper, String paramPrefix) {
        return whereClauseFromFilter(filter, values, mapper, paramPrefix, 0);
    }

    private String whereClauseFromFilter(Filter filter, Map<String, Object> values, AttributeNameMapper mapper, String paramPrefix, int depth) {
        if (depth > MAX_FILTER_DEPTH) {
            throw new IllegalArgumentException("Filter too deeply nested");
        }
        return switch (filter.getFilterType()) {
            case AND -> buildCombiningClause(filter, " AND ", values, mapper, paramPrefix, depth);
            case OR -> buildCombiningClause(filter, " OR ", values, mapper, paramPrefix, depth);
            case EQUAL -> comparisonClause(filter, "=", values, "", "", paramPrefix);
            case CONTAINS -> comparisonClause(filter, "LIKE", values, "%", "%", paramPrefix);
            case STARTS_WITH -> comparisonClause(filter, "LIKE", values, "", "%", paramPrefix);
            case PRESENT -> getAttributeName(filter, mapper) + " IS NOT NULL";
            case GREATER_THAN -> comparisonClause(filter, ">", values, "", "", paramPrefix);
            case GREATER_OR_EQUAL -> comparisonClause(filter, ">=", values, "", "", paramPrefix);
            case LESS_THAN -> comparisonClause(filter, "<", values, "", "", paramPrefix);
            case LESS_OR_EQUAL -> comparisonClause(filter, "<=", values, "", "", paramPrefix);
            default -> throw new IllegalArgumentException("Unsupported filter type: " + filter.getFilterType());
        };
    }

    private String comparisonClause(Filter filter,
            String comparator,
            Map<String, Object> values,
            String valuePrefix,
            String valueSuffix,
            String paramPrefix) {
        String pName = getParamName(values, paramPrefix);
        String paramName = ":" + pName;
        ValueNode compValue = filter.getComparisonValue();
        if (compValue == null || compValue.isNull()) {
            return getAttributeName(filter, mapper) + " IS NULL";
        } else if (compValue.isString()) {
            Object value = getStringOrDate(compValue.asString());
            if (value instanceof String) {
                //lower is used to satisfy the requirement that all quoted values are compared case insensitive
                switch (filter.getAttributePath().toString().toLowerCase()) {
                    case "client_secret":
                    case "password":
                    case "salt":
                        value = "";
                        break;
                    default:
                        break;
                }
                values.put(pName, valuePrefix + value + valueSuffix);
                if (isDbCaseInsensitive()) {
                    return getAttributeName(filter, mapper) + " " + comparator + " " + paramName;
                } else {
                    return "LOWER(" + getAttributeName(filter, mapper) + ") " + comparator + " LOWER(" + paramName + ")";
                }
            } else {
                values.put(pName, value);
                return getAttributeName(filter, mapper) + " " + comparator + " " + paramName;
            }
        } else if (compValue.isBoolean()) {
            values.put(pName, compValue.booleanValue());
            return getAttributeName(filter, mapper) + " " + comparator + " " + paramName;
        } else if (compValue.isNumber()) {
            values.put(pName, compValue.doubleValue());
            return getAttributeName(filter, mapper) + " " + comparator + " " + paramName;
        } else {
            throw new IllegalArgumentException("Invalid non-quoted value [" + filter.getAttributePath() +
                    " : " + compValue + "]");
        }
    }

    private String getAttributeName(Filter filter, AttributeNameMapper mapper) {
        String name = filter.getAttributePath().toString();
        name = mapper.mapToInternal(name);
        return name.replace("meta.", "");
    }

    private String getParamName(Map<String, Object> values, String paramPrefix) {
        return paramPrefix + values.size();
    }

    private Object getStringOrDate(String s) {
        try {
            DateFormat timestampFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX");
            return timestampFormat.parse(s);
        } catch (ParseException _) {
            return s;
        }
    }

    @Override
    public String map(String attribute) {
        return hasText(attribute) ? mapper.mapToInternal(attribute) : attribute;
    }

    public String getJoinName() {
        return mapper instanceof JoinAttributeNameMapper joinAttributeNameMapper ? joinAttributeNameMapper.getName() : UaaStringUtils.EMPTY_STRING;
    }
}
