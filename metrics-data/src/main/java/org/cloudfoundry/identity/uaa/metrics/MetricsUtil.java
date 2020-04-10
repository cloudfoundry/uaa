package org.cloudfoundry.identity.uaa.metrics;

public class MetricsUtil {
  public static final String GLOBAL_GROUP = "uaa.global.metrics";

  public static double addAverages(
      double oldCount, double oldAverage, double newCount, double newAverage) {
    if (newCount == 0) {
      return oldAverage;
    }
    return ((oldCount) / (newCount + oldCount) * oldAverage)
        + (newCount / (newCount + oldCount) * newAverage);
  }

  public static double addToAverage(
      double oldCount, double oldAverage, double newCount, double newTotalTime) {
    if (newCount == 0) {
      return oldAverage;
    }
    double newAverage = newTotalTime / newCount;
    return ((oldCount) / (newCount + oldCount) * oldAverage)
        + (newCount / (newCount + oldCount) * newAverage);
  }

  public static class MutableLong {
    long value;

    public MutableLong(long value) {
      this.value = value;
    }

    public long get() {
      return value;
    }

    public void set(long value) {
      this.value = value;
    }

    public void add(long value) {
      this.value += value;
    }

    @Override
    public String toString() {
      return Long.valueOf(get()).toString();
    }
  }

  public static class MutableDouble {
    double value;

    public MutableDouble(double value) {
      this.value = value;
    }

    public double get() {
      return value;
    }

    public void set(double value) {
      this.value = value;
    }

    public void add(double value) {
      this.value += value;
    }

    @Override
    public String toString() {
      return Double.valueOf(get()).toString();
    }
  }
}
