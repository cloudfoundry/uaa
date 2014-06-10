/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.jdbc;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.unboundid.scim.sdk.SCIMException;
import com.unboundid.scim.sdk.SCIMFilter;
import com.unboundid.scim.sdk.SCIMFilterType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.rest.jdbc.SearchQueryConverter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class ScimSearchQueryConverter implements SearchQueryConverter {

    private static Log logger = LogFactory.getLog(ScimSearchQueryConverter.class);

    private AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.<String, String> emptyMap());

    public void setAttributeNameMapper(AttributeNameMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public ProcessedFilter convert(String filter, String sortBy, boolean ascending) {
        return convert(filter, sortBy, ascending, mapper);
    }

    @Override
    public ProcessedFilter convert(String filter, String sortBy, boolean ascending, AttributeNameMapper mapper) {
        Map<String, Object> values = new HashMap<String, Object>();
        String where = StringUtils.hasText(filter) ? getWhereClause(filter, sortBy, ascending, values, mapper) : null;
        return new ProcessedFilter(where, values);
    }

    private String getWhereClause(String filter, String sortBy, boolean ascending, Map<String, Object> values, AttributeNameMapper mapper) {
        String whereClause = null;
        try {
            SCIMFilter scimFilter = SCIMFilter.parse(filter);
            whereClause = createFilter(scimFilter, values, mapper);
            if (sortBy != null) {
                sortBy = mapper.mapToInternal(sortBy);
                // Need to add "asc" or "desc" explicitly to ensure that the pattern
                // splitting below works
                whereClause += " ORDER BY " + sortBy + (ascending ? " ASC" : " DESC");
            }
        } catch (SCIMException e) {
            logger.debug("Unable to parse " + filter, e);
            throw new IllegalArgumentException("Invalid SCIM Filter:"+filter+" Message:"+e.getMessage());
        }
        return whereClause;
    }

    private String createFilter(SCIMFilter filter, Map<String,Object> values, AttributeNameMapper mapper) {
        switch (filter.getFilterType()) {
            case AND:
                return "(" + createFilter(filter.getFilterComponents().get(0), values, mapper) + " AND " + createFilter(filter.getFilterComponents().get(1), values, mapper) + ")";
            case OR:
                return "(" + createFilter(filter.getFilterComponents().get(0), values, mapper) + " OR " + createFilter(filter.getFilterComponents().get(1), values, mapper) + ")";
            case EQUALITY:
                return comparisonClause(filter, "=", values, "", "");
            case CONTAINS:
                return comparisonClause(filter, "LIKE", values, "%", "%");
            case STARTS_WITH:
                return comparisonClause(filter, "LIKE", values, "", "%");
            case PRESENCE:
                return getAttributeName(filter, mapper) + " IS NOT NULL";
            case GREATER_THAN:
                return comparisonClause(filter, ">", values, "", "");
            case GREATER_OR_EQUAL:
                return comparisonClause(filter, ">=", values, "", "");
            case LESS_THAN:
                return comparisonClause(filter, "<", values, "", "");
            case LESS_OR_EQUAL:
                return comparisonClause(filter, "<=", values, "", "");
        }
        return null;
    }

    protected String comparisonClause(SCIMFilter filter, String comparator, Map<String, Object> values, String valuePrefix, String valueSuffix) {
        String pName = getParamName(filter, values);
        String paramName = ":"+pName;
        if (filter.getFilterValue() == null) {
            return getAttributeName(filter, mapper) + " IS NULL";
        } else if (filter.isQuoteFilterValue()) {
            Object value = getStringOrDate(filter.getFilterValue());
            if (value instanceof String) {
                //TODO - why lower?
                values.put(pName, valuePrefix+value+valueSuffix);
                return "LOWER(" + getAttributeName(filter, mapper) + ") "+comparator+" LOWER(" + paramName+")";
            } else {
                values.put(pName, value);
                return getAttributeName(filter, mapper) + " "+comparator+" " + paramName;
            }


        } else {
            try {
                values.put(pName, Double.parseDouble(filter.getFilterValue()));
            } catch (NumberFormatException x) {
                values.put(pName, filter.getFilterValue());
            }
            return getAttributeName(filter, mapper) + " "+comparator+" " + paramName;
        }
    }

    protected String getAttributeName(SCIMFilter filter, AttributeNameMapper mapper) {
        String name = filter.getFilterAttribute().getAttributeName();
        String subName = filter.getFilterAttribute().getSubAttributeName();
        if (StringUtils.hasText(subName)) {
            name = name + "." + subName;
        }
        name = mapper.mapToInternal(name);
        return name.replace("meta.", "");
    }

    protected String getParamName(SCIMFilter filter, Map<String, Object> values) {
        return "__value_" + values.size();
    }

    protected Object getStringOrDate(String s) {
        try {
            DateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            return TIMESTAMP_FORMAT.parse(s);
        } catch (ParseException x) {
            return s;
        }
    }
}
