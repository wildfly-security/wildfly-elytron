/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl;

import static org.wildfly.common.math.HashMath.*;

import java.util.Arrays;
import java.util.function.Predicate;

import javax.net.ssl.SSLSession;

import org.wildfly.common.Assert;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class SaslMechanismPredicate {
    private int hashCode;

    SaslMechanismPredicate() {
    }

    abstract boolean test(String mechName, final SSLSession sslSession);

    public String toString() {
        StringBuilder b = new StringBuilder();
        toString(b);
        return b.toString();
    }

    abstract void toString(StringBuilder b);

    public static SaslMechanismPredicate matchTrue() {
        return TRUE;
    }

    public static SaslMechanismPredicate matchFalse() {
        return FALSE;
    }

    public static SaslMechanismPredicate matchAll(SaslMechanismPredicate... predicates) {
        return new AllPredicate(predicates);
    }

    public static SaslMechanismPredicate matchAllOrNone(SaslMechanismPredicate... predicates) {
        return new AllOrNonePredicate(predicates);
    }

    public static SaslMechanismPredicate matchAny(SaslMechanismPredicate... predicates) {
        return new AnyPredicate(predicates);
    }

    public static SaslMechanismPredicate matchNot(SaslMechanismPredicate predicate) {
        Assert.checkNotNullParam("predicate", predicate);
        return predicate.not();
    }

    public static SaslMechanismPredicate matchIf(SaslMechanismPredicate conditionPredicate, SaslMechanismPredicate truePredicate, SaslMechanismPredicate falsePredicate) {
        Assert.checkNotNullParam("conditionPredicate", conditionPredicate);
        Assert.checkNotNullParam("truePredicate", truePredicate);
        Assert.checkNotNullParam("falsePredicate", falsePredicate);
        return new IfPredicate(conditionPredicate, truePredicate, falsePredicate);
    }

    public static SaslMechanismPredicate matchExact(String name) {
        Assert.checkNotNullParam("name", name);
        return new ExactPredicate(name);
    }

    public static SaslMechanismPredicate matchHashFunction(String digest) {
        Assert.checkNotNullParam("digest", digest);
        return new HashPredicate(digest);
    }

    public static SaslMechanismPredicate matchPlus() {
        return PLUS;
    }

    public static SaslMechanismPredicate matchMutual() {
        return MUTUAL;
    }

    public static SaslMechanismPredicate matchFamily(String name) {
        Assert.checkNotNullParam("name", name);
        final Predicate<String> predicate;
        switch (name) {
            case "DIGEST": predicate = SaslMechanismInformation.DIGEST; break;
            case "EAP": predicate = SaslMechanismInformation.EAP; break;
            case "GS2": predicate = SaslMechanismInformation.GS2; break;
            case "SCRAM": predicate = SaslMechanismInformation.SCRAM; break;
            case "IEC-ISO-9798": predicate = SaslMechanismInformation.IEC_ISO_9798; break;
            default: predicate = s -> false; break;
        }
        return new FamilyPredicate(predicate, name);
    }

    public static SaslMechanismPredicate matchTLSActive() {
        return TLS_ACTIVE;
    }

    public final boolean equals(final Object obj) {
        return obj instanceof SaslMechanismPredicate && equals((SaslMechanismPredicate) obj);
    }

    public abstract boolean equals(SaslMechanismPredicate other);

    public final int hashCode() {
        int hashCode = this.hashCode;
        if (hashCode == 0) {
            hashCode = calcHashCode();
            if (hashCode == 0) {
                hashCode = 1;
            }
            return this.hashCode = hashCode;
        }
        return hashCode;
    }

    abstract int calcHashCode();

    SaslMechanismPredicate not() {
        return new NotPredicate(this);
    }

    static final BooleanPredicate TRUE = new BooleanPredicate(true);
    static final BooleanPredicate FALSE = new BooleanPredicate(false);

    static final SaslMechanismPredicate TLS_ACTIVE = new SaslMechanismPredicate() {
        boolean test(final String mechName, final SSLSession sslSession) {
            return sslSession != null;
        }

        void toString(final StringBuilder b) {
            b.append("#TLS");
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return this == other;
        }

        int calcHashCode() {
            return getClass().hashCode();
        }
    };

    static final SaslMechanismPredicate PLUS = new SaslMechanismPredicate() {
        boolean test(final String mechName, final SSLSession sslSession) {
            return sslSession != null && SaslMechanismInformation.BINDING.test(mechName);
        }

        void toString(final StringBuilder b) {
            b.append("#PLUS");
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return this == other;
        }

        int calcHashCode() {
            return getClass().hashCode();
        }
    };

    static final SaslMechanismPredicate MUTUAL = new SaslMechanismPredicate() {
        boolean test(final String mechName, final SSLSession sslSession) {
            return sslSession != null && SaslMechanismInformation.MUTUAL.test(mechName);
        }

        void toString(final StringBuilder b) {
            b.append("#MUTUAL");
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return this == other;
        }

        int calcHashCode() {
            return getClass().hashCode();
        }
    };

    static final class BooleanPredicate extends SaslMechanismPredicate {
        private final boolean value;

        BooleanPredicate(final boolean value) {
            this.value = value;
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            return value;
        }

        void toString(final StringBuilder b) {
            b.append(value);
        }

        SaslMechanismPredicate not() {
            return value ? FALSE : TRUE;
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return this == other;
        }

        int calcHashCode() {
            return getClass().hashCode() * 19 + (value ? 1 : 0);
        }
    }

    abstract static class MultiPredicate extends SaslMechanismPredicate {
        final SaslMechanismPredicate[] predicates;

        MultiPredicate(final SaslMechanismPredicate[] predicates) {
            for (int i = 0; i < predicates.length; i++) {
                SaslMechanismPredicate predicate = predicates[i];
                Assert.checkNotNullArrayParam("predicates", i, predicate);
            }
            this.predicates = predicates;
        }

        void toString(final StringBuilder b) {
            b.append('(');
            final int length = predicates.length;
            if (length > 0) {
                b.append(predicates[0]);
                for (int i = 1; i < length; i++) {
                    appendOperator(b);
                    b.append(predicates[i]);
                }
            }
            b.append(')');
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return other.getClass() == getClass() && Arrays.equals(predicates, ((MultiPredicate)other).predicates);
        }

        int calcHashCode() {
            int hc = getClass().hashCode() * 19;
            for (SaslMechanismPredicate predicate : predicates) {
                hc = multiHashUnordered(hc, predicate.calcHashCode());
            }
            return hc;
        }

        abstract void appendOperator(final StringBuilder b);
    }

    static final class AllPredicate extends MultiPredicate {
        AllPredicate(final SaslMechanismPredicate[] predicates) {
            super(predicates);
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            for (SaslMechanismPredicate predicate : predicates) {
                if (! predicate.test(mechName, sslSession)) {
                    return false;
                }
            }
            return true;
        }

        void appendOperator(final StringBuilder b) {
            b.append('&').append('&');
        }
    }

    static final class AllOrNonePredicate extends MultiPredicate {
        AllOrNonePredicate(final SaslMechanismPredicate[] predicates) {
            super(predicates);
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            final int length = predicates.length;
            if (length == 0) {
                return true;
            }
            boolean val = predicates[0].test(mechName, sslSession);
            for (int i = 1; i < length; i++) {
                final SaslMechanismPredicate predicate = predicates[i];
                if (val != predicate.test(mechName, sslSession)) {
                    return false;
                }
            }
            return true;
        }

        void appendOperator(final StringBuilder b) {
            b.append('=').append('=');
        }
    }

    static final class AnyPredicate extends MultiPredicate {
        AnyPredicate(final SaslMechanismPredicate[] predicates) {
            super(predicates);
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            for (SaslMechanismPredicate predicate : predicates) {
                if (predicate.test(mechName, sslSession)) {
                    return true;
                }
            }
            return false;
        }

        void appendOperator(final StringBuilder b) {
            b.append('|').append('|');
        }
    }

    static class NotPredicate extends SaslMechanismPredicate {
        private final SaslMechanismPredicate predicate;

        NotPredicate(final SaslMechanismPredicate predicate) {
            this.predicate = predicate;
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            return ! predicate.test(mechName, sslSession);
        }

        void toString(final StringBuilder b) {
            b.append('!');
            predicate.toString(b);
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return other instanceof NotPredicate && predicate.equals(((NotPredicate) other).predicate);
        }

        int calcHashCode() {
            return getClass().hashCode() * 19 + predicate.calcHashCode();
        }

        SaslMechanismPredicate not() {
            return predicate;
        }
    }

    static class ExactPredicate extends SaslMechanismPredicate {
        private final String mechName;

        ExactPredicate(final String mechName) {
            this.mechName = mechName;
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            return this.mechName.equals(mechName);
        }

        void toString(final StringBuilder b) {
            b.append(mechName);
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return other instanceof ExactPredicate && this.mechName.equals(((ExactPredicate) other).mechName);
        }

        int calcHashCode() {
            return getClass().hashCode() * 19 + mechName.hashCode();
        }
    }

    static class FamilyPredicate extends SaslMechanismPredicate {
        private final Predicate<String> predicate;
        private final String name;

        FamilyPredicate(final Predicate<String> predicate, final String name) {
            this.predicate = predicate;
            this.name = name;
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            return predicate.test(mechName);
        }

        void toString(final StringBuilder b) {
            b.append("#FAMILY(").append(name).append(')');
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return other instanceof FamilyPredicate && equals((FamilyPredicate) other);
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        private boolean equals(final FamilyPredicate other) {
            return predicate.equals(other.predicate) && name.equals(other.name);
        }

        int calcHashCode() {
            return multiHashOrdered(multiHashOrdered(getClass().hashCode(), predicate.hashCode()), name.hashCode());
        }
    }

    static class IfPredicate extends SaslMechanismPredicate {
        private final SaslMechanismPredicate conditionPredicate;
        private final SaslMechanismPredicate truePredicate;
        private final SaslMechanismPredicate falsePredicate;

        IfPredicate(final SaslMechanismPredicate conditionPredicate, final SaslMechanismPredicate truePredicate, final SaslMechanismPredicate falsePredicate) {
            this.conditionPredicate = conditionPredicate;
            this.truePredicate = truePredicate;
            this.falsePredicate = falsePredicate;
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            return conditionPredicate.test(mechName, sslSession) ? truePredicate.test(mechName, sslSession) : falsePredicate.test(mechName, sslSession);
        }

        void toString(final StringBuilder b) {
            b.append('(').append(conditionPredicate).append('?').append(truePredicate).append(':').append(falsePredicate).append(')');
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return this == other || other instanceof IfPredicate && equals((IfPredicate) other);
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        private boolean equals(final IfPredicate other) {
            return conditionPredicate.equals(other.conditionPredicate) && truePredicate.equals(other.truePredicate) && falsePredicate.equals(other.falsePredicate);
        }

        int calcHashCode() {
            return multiHashOrdered(multiHashOrdered(multiHashOrdered(getClass().hashCode(), conditionPredicate.hashCode()), truePredicate.hashCode()), falsePredicate.hashCode());
        }
    }

    static class HashPredicate extends SaslMechanismPredicate {
        private final String digest;

        HashPredicate(final String digest) {
            this.digest = digest;
        }

        boolean test(final String mechName, final SSLSession sslSession) {
            switch (digest) {
                case "MD5": return SaslMechanismInformation.HASH_MD5.test(mechName);
                case "SHA-1": return SaslMechanismInformation.HASH_SHA.test(mechName);
                case "SHA-256": return SaslMechanismInformation.HASH_SHA_256.test(mechName);
                case "SHA-384": return SaslMechanismInformation.HASH_SHA_384.test(mechName);
                case "SHA-512": return SaslMechanismInformation.HASH_SHA_512.test(mechName);
                default: return false;
            }
        }

        void toString(final StringBuilder b) {
            b.append("#HASH(").append(digest).append(')');
        }

        @SuppressWarnings("checkstyle:equalshashcode")
        public boolean equals(final SaslMechanismPredicate other) {
            return other instanceof HashPredicate && digest.equals(((HashPredicate) other).digest);
        }

        int calcHashCode() {
            return 0;
        }
    }
}
