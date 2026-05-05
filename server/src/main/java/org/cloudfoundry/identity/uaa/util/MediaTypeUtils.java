package org.cloudfoundry.identity.uaa.util;

import org.springframework.http.MediaType;
import org.springframework.util.Assert;

import java.util.Comparator;
import java.util.List;

/**
 * Utility methods and comparators for working with MediaType instances.
 * Replaces the deprecated MediaType.QUALITY_VALUE_COMPARATOR and MediaType.sortByQualityValue
 * that were removed in Spring Framework 7.
 */
public final class MediaTypeUtils {

    private MediaTypeUtils() {
    }

    /**
     * Comparator for sorting media types by quality value.
     * This implementation preserves the exact sorting logic from Spring Framework 6's
     * MediaType.QUALITY_VALUE_COMPARATOR.
     */
    public static final Comparator<MediaType> BY_QUALITY_VALUE = (mediaType1, mediaType2) -> {
        double quality1 = mediaType1.getQualityValue();
        double quality2 = mediaType2.getQualityValue();
        int qualityComparison = Double.compare(quality2, quality1);
        if (qualityComparison != 0) {
            return qualityComparison;  // audio/*;q=0.7 < audio/*;q=0.3
        } else if (mediaType1.isWildcardType() && !mediaType2.isWildcardType()) {  // */* < audio/*
            return 1;
        } else if (mediaType2.isWildcardType() && !mediaType1.isWildcardType()) {  // audio/* > */*
            return -1;
        } else if (!mediaType1.getType().equals(mediaType2.getType())) {  // audio/basic == text/html
            return 0;
        } else {  // mediaType1.getType().equals(mediaType2.getType())
            if (mediaType1.isWildcardSubtype() && !mediaType2.isWildcardSubtype()) {  // audio/* < audio/basic
                return 1;
            } else if (mediaType2.isWildcardSubtype() && !mediaType1.isWildcardSubtype()) {  // audio/basic > audio/*
                return -1;
            } else if (!mediaType1.getSubtype().equals(mediaType2.getSubtype())) {  // audio/basic == audio/wave
                return 0;
            } else {
                int paramsSize1 = mediaType1.getParameters().size();
                int paramsSize2 = mediaType2.getParameters().size();
                return Integer.compare(paramsSize2, paramsSize1);  // audio/basic;level=1 < audio/basic
            }
        }
    };

    /**
     * Sorts the given list of {@code MediaType} objects by quality value.
     * This method replicates Spring Framework 6's deprecated MediaType.sortByQualityValue()
     * behavior.
     *
     * @param mediaTypes the list to sort
     * @throws IllegalArgumentException if the list is {@code null}
     */
    public static void sortByQualityValue(List<MediaType> mediaTypes) {
        Assert.notNull(mediaTypes, "'mediaTypes' must not be null");
        if (mediaTypes.size() > 1) {
            mediaTypes.sort(BY_QUALITY_VALUE);
        }
    }
}
