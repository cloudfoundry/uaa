package org.cloudfoundry.identity.uaa.util;

import org.springframework.http.MediaType;

import java.util.Comparator;

/**
 * Comparators for sorting MediaType instances.
 * Replaces the deprecated MediaType.QUALITY_VALUE_COMPARATOR and MediaType.sortByQualityValue
 * that were removed in Spring Framework 7.
 */
public final class MediaTypeComparators {

    private MediaTypeComparators() {}

    /**
     * Comparator for sorting media types by quality value.
     * This implementation preserves the exact sorting logic from Spring Framework 6's
     * MediaType.QUALITY_VALUE_COMPARATOR to ensure content negotiation works correctly.
     */
    public static final Comparator<MediaType> BY_QUALITY_VALUE = (mediaType1, mediaType2) -> {
        double quality1 = mediaType1.getQualityValue();
        double quality2 = mediaType2.getQualityValue();
        int qualityComparison = Double.compare(quality2, quality1);
        if (qualityComparison != 0) {
            return qualityComparison;  // audio/*;q=0.7 < audio/*;q=0.3
        }
        else if (mediaType1.isWildcardType() && !mediaType2.isWildcardType()) {  // */* < audio/*
            return 1;
        }
        else if (mediaType2.isWildcardType() && !mediaType1.isWildcardType()) {  // audio/* > */*
            return -1;
        }
        else if (!mediaType1.getType().equals(mediaType2.getType())) {  // audio/basic == text/html
            return 0;
        }
        else {  // mediaType1.getType().equals(mediaType2.getType())
            if (mediaType1.isWildcardSubtype() && !mediaType2.isWildcardSubtype()) {  // audio/* < audio/basic
                return 1;
            }
            else if (mediaType2.isWildcardSubtype() && !mediaType1.isWildcardSubtype()) {  // audio/basic > audio/*
                return -1;
            }
            else if (!mediaType1.getSubtype().equals(mediaType2.getSubtype())) {  // audio/basic == audio/wave
                return 0;
            }
            else {
                int paramsSize1 = mediaType1.getParameters().size();
                int paramsSize2 = mediaType2.getParameters().size();
                return Integer.compare(paramsSize2, paramsSize1);  // audio/basic;level=1 < audio/basic
            }
        }
    };
}
