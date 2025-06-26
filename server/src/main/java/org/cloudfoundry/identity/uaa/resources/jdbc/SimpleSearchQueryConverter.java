package org.cloudfoundry.identity.uaa.resources.jdbc;

import com.unboundid.scim.sdk.AttributePath;
import com.unboundid.scim.sdk.InvalidResourceException;
import com.unboundid.scim.sdk.SCIMException;
import com.unboundid.scim.sdk.SCIMFilter;
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

import static com.unboundid.scim.sdk.SCIMException.createException;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter.ProcessedFilter.ORDER_BY;
import static org.springframework.util.StringUtils.hasText;

public class SimpleSearchQueryConverter implements SearchQueryConverter {

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
            final SCIMFilter zoneIdFilter = SCIMFilter.createEqualityFilter(
                    AttributePath.parse("identity_zone_id"),
                    zoneId);
            SCIMFilter fullFilter;
            if (hasText(filter)) {
                fullFilter = SCIMFilter.createAndFilter(asList(scimFilter(filter), zoneIdFilter));
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
        } catch (SCIMException e) {
            logger.debug("Unable to parse {}", filter, e);
            throw new IllegalArgumentException("Invalid SCIM Filter: " + filter + "; Message: " + e.getMessage());
        }
    }

    @Override
    public MultiValueMap<String, Object> getFilterValues(String filter, List<String> validAttributes) throws IllegalArgumentException {
        try {
            SCIMFilter scimFilter = SCIMFilter.parse(filter);
            validateFilterAttributes(scimFilter, validAttributes);
            MultiValueMap<String, Object> result = new LinkedMultiValueMap<>();
            extractValues(scimFilter, result);
            return result;
        } catch (SCIMException x) {
            throw new IllegalArgumentException(x.getMessage());
        }
    }

    private SCIMFilter scimFilter(String filter) throws SCIMException {
        SCIMFilter scimFilter;
        try {
            scimFilter = SCIMFilter.parse(filter);
        } catch (SCIMException e) {
            logger.debug("Attempting legacy scim filter conversion for [{}]", filter, e);
            filter = filter.replaceAll("'", "\"");
            scimFilter = SCIMFilter.parse(filter);
        }
        validateFilterAttributes(scimFilter, VALID_ATTRIBUTE_NAMES);
        return scimFilter;
    }

    private void validateFilterAttributes(SCIMFilter filter, List<String> validAttributeNames) throws SCIMException {
        List<String> invalidAttributes = new LinkedList<>();
        validateFilterAttributes(filter, invalidAttributes, validAttributeNames);
        if (!invalidAttributes.isEmpty()) {
            throw new InvalidResourceException("Invalid filter attributes:" + StringUtils.collectionToCommaDelimitedString(invalidAttributes));
        }
    }

    private void validateFilterAttributes(SCIMFilter filter, List<String> invalidAttribues, List<String> validAttributeNames) {
        if (filter.getFilterAttribute() != null && filter.getFilterAttribute().getAttributeName() != null) {
            String name = filter.getFilterAttribute().getAttributeName();
            if (filter.getFilterAttribute().getSubAttributeName() != null) {
                name = name + "." + filter.getFilterAttribute().getSubAttributeName();
            }
            if (!validAttributeNames.contains(name.toLowerCase())) {
                invalidAttribues.add(name);
            }
        }
        for (SCIMFilter subfilter : ofNullable(filter.getFilterComponents()).orElse(emptyList())) {
            validateFilterAttributes(subfilter, invalidAttribues, validAttributeNames);
        }
    }

    private void extractValues(SCIMFilter filter, MultiValueMap<String, Object> values) throws SCIMException {
        switch (filter.getFilterType()) {
            case AND:
                extractValues(filter.getFilterComponents().getFirst(), values);
                extractValues(filter.getFilterComponents().get(1), values);
                break;
            case OR:
                throw createException(400, "[or] operator is not supported.");
            case EQUALITY:
                Object value = getStringOrDate(filter.getFilterValue());
                String key = filter.getFilterAttribute().getAttributeName();
                values.add(key, value);
                break;
            case CONTAINS:
                throw createException(400, "[co] operator is not supported.");
            case STARTS_WITH:
                throw createException(400, "[sw] operator is not supported.");
            case PRESENCE:
                throw createException(400, "[pr] operator is not supported.");
            case GREATER_THAN:
                throw createException(400, "[gt] operator is not supported.");
            case GREATER_OR_EQUAL:
                throw createException(400, "[ge] operator is not supported.");
            case LESS_THAN:
                throw createException(400, "[lt] operator is not supported.");
            case LESS_OR_EQUAL:
                throw createException(400, "[le] operator is not supported.");
            default:
                throw createException(400, "Unknown filter operator:" + filter.getFilterType());
        }
    }

    private String whereClauseFromFilter(SCIMFilter filter, Map<String, Object> values, AttributeNameMapper mapper, String paramPrefix) {
        switch (filter.getFilterType()) {
            case AND:
                return "(" + whereClauseFromFilter(filter.getFilterComponents().getFirst(), values, mapper, paramPrefix) + " AND " + whereClauseFromFilter(filter.getFilterComponents().get(1), values, mapper, paramPrefix) + ")";
            case OR:
                return "(" + whereClauseFromFilter(filter.getFilterComponents().getFirst(), values, mapper, paramPrefix) + " OR " + whereClauseFromFilter(filter.getFilterComponents().get(1), values, mapper, paramPrefix) + ")";
            case EQUALITY:
                return comparisonClause(filter, "=", values, "", "", paramPrefix);
            case CONTAINS:
                return comparisonClause(filter, "LIKE", values, "%", "%", paramPrefix);
            case STARTS_WITH:
                return comparisonClause(filter, "LIKE", values, "", "%", paramPrefix);
            case PRESENCE:
                return getAttributeName(filter, mapper) + " IS NOT NULL";
            case GREATER_THAN:
                return comparisonClause(filter, ">", values, "", "", paramPrefix);
            case GREATER_OR_EQUAL:
                return comparisonClause(filter, ">=", values, "", "", paramPrefix);
            case LESS_THAN:
                return comparisonClause(filter, "<", values, "", "", paramPrefix);
            case LESS_OR_EQUAL:
                return comparisonClause(filter, "<=", values, "", "", paramPrefix);
        }
        return null;
    }

    private String comparisonClause(SCIMFilter filter,
            String comparator,
            Map<String, Object> values,
            String valuePrefix,
            String valueSuffix,
            String paramPrefix) {
        String pName = getParamName(values, paramPrefix);
        String paramName = ":" + pName;
        if (filter.getFilterValue() == null) {
            return getAttributeName(filter, mapper) + " IS NULL";
        } else if (filter.isQuoteFilterValue()) {
            Object value = getStringOrDate(filter.getFilterValue());
            if (value instanceof String) {
                //lower is used to satisfy the requirement that all quoted values are compared case insensitive
                switch (filter.getFilterAttribute().getAttributeName().toLowerCase()) {
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
                    return "" + getAttributeName(filter, mapper) + " " + comparator + " " + paramName + "";
                } else {
                    return "LOWER(" + getAttributeName(filter, mapper) + ") " + comparator + " LOWER(" + paramName + ")";
                }
            } else {
                values.put(pName, value);
                return getAttributeName(filter, mapper) + " " + comparator + " " + paramName;
            }
        } else {
            try {
                values.put(pName, Double.parseDouble(filter.getFilterValue()));
            } catch (NumberFormatException x) {
                if ("true".equalsIgnoreCase(filter.getFilterValue())) {
                    values.put(pName, Boolean.TRUE);
                } else if ("false".equalsIgnoreCase(filter.getFilterValue())) {
                    values.put(pName, Boolean.FALSE);
                } else {
                    throw new IllegalArgumentException("Invalid non quoted value [" + filter.getFilterAttribute() +
                            " : " + filter.getFilterValue() + "]");
                }
            }
            return getAttributeName(filter, mapper) + " " + comparator + " " + paramName;
        }
    }

    private String getAttributeName(SCIMFilter filter, AttributeNameMapper mapper) {
        String name = filter.getFilterAttribute().getAttributeName();
        String subName = filter.getFilterAttribute().getSubAttributeName();
        if (hasText(subName)) {
            name = name + "." + subName;
        }
        name = mapper.mapToInternal(name);
        return name.replace("meta.", "");
    }

    private String getParamName(Map<String, Object> values, String paramPrefix) {
        return paramPrefix + values.size();
    }

    private Object getStringOrDate(String s) {
        try {
            DateFormat timestampFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            return timestampFormat.parse(s);
        } catch (ParseException x) {
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
