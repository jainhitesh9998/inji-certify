package io.mosip.certify.keyprovider.jca;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * The order of key version labels ({@code mdl-dsc@2026-11}, {@code mdl-dsc@2026-11.2}): runs of digits compare as
 * numbers and everything else as text, so {@code 2026-11.10} comes after {@code 2026-11.2} and {@code 2026-11} before
 * {@code 2026-11.1}. It matches the {@code <prefix>@yyyy-MM[.N]} labels {@code certify-cli pki dsc rotate} writes (M-07)
 * and orders any other label deterministically. A missing label (an unversioned entry) comes first.
 */
public final class VersionLabels {

    /** Null (no version) first, then the numeric-aware order described on the class. */
    public static final Comparator<String> ORDER = VersionLabels::compare;

    private VersionLabels() {}

    public static int compare(String a, String b) {
        if (a == null || b == null) {
            return a == null ? (b == null ? 0 : -1) : 1;
        }
        List<String> left = tokens(a);
        List<String> right = tokens(b);
        for (int i = 0; i < Math.min(left.size(), right.size()); i++) {
            int order = compareToken(left.get(i), right.get(i));
            if (order != 0) {
                return order;
            }
        }
        int bySize = Integer.compare(left.size(), right.size());
        return bySize != 0 ? bySize : a.compareTo(b);
    }

    /** The version label of an alias, the text after its last {@code @}; {@code null} when it has none. */
    public static String versionOf(String alias) {
        int at = alias.lastIndexOf('@');
        return at > 0 ? alias.substring(at + 1) : null;
    }

    /** The alias without its version label. */
    public static String baseOf(String alias) {
        int at = alias.lastIndexOf('@');
        return at > 0 ? alias.substring(0, at) : alias;
    }

    private static int compareToken(String x, String y) {
        boolean xDigits = digit(x.charAt(0));
        boolean yDigits = digit(y.charAt(0));
        if (xDigits && yDigits) {
            String xs = stripZeros(x);
            String ys = stripZeros(y);
            int byLength = Integer.compare(xs.length(), ys.length());
            return byLength != 0 ? byLength : xs.compareTo(ys);
        }
        return x.compareTo(y);
    }

    private static String stripZeros(String digits) {
        int i = 0;
        while (i < digits.length() - 1 && digits.charAt(i) == '0') {
            i++;
        }
        return digits.substring(i);
    }

    private static boolean digit(char c) {
        return c >= '0' && c <= '9';
    }

    private static List<String> tokens(String label) {
        List<String> tokens = new ArrayList<>();
        int start = 0;
        for (int i = 1; i <= label.length(); i++) {
            if (i == label.length()
                    || digit(label.charAt(i)) != digit(label.charAt(i - 1))) {
                tokens.add(label.substring(start, i));
                start = i;
            }
        }
        return tokens;
    }
}
