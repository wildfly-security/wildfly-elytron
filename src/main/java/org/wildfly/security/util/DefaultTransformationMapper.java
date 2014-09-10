/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.util;

import static org.wildfly.security.util.TransformationSpec.HIGH_STRENGTH;
import static org.wildfly.security.util.TransformationSpec.MEDIUM_STRENGTH;
import static org.wildfly.security.util.TransformationSpec.LOW_STRENGTH;
import static org.wildfly.security.util.TransformationSpec.NO_KEY;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;

/**
 * Default implementation of TransformationMapper interface.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class DefaultTransformationMapper implements TransformationMapper {

    protected HashMap<String, TransformationSpec[]> transformations = new HashMap<String, TransformationSpec[]>();

    public DefaultTransformationMapper() {

        transformations.put("DIGEST-MD5", new TransformationSpec[] { // TODO: once digest-md5 PR will be merged change this to
                                                                     // JBOSS_DIGEST_MD5
                new TransformationSpec("3des", "DESede/CBC/NoPadding", NO_KEY, HIGH_STRENGTH + 1, "SunJCA"),
                        new TransformationSpec("rc4", "RC4", 128, HIGH_STRENGTH, "SunJCA"),
                        new TransformationSpec("des", "DES/CBC/NoPadding", NO_KEY, MEDIUM_STRENGTH + 1, "SunJCA"),
                        new TransformationSpec("rc4-56", "RC4", 56, MEDIUM_STRENGTH, "SunJCA"),
                        new TransformationSpec("rc4-40", "RC4", 40, LOW_STRENGTH, "SunJCA") });

        // sort all transformation arrays descending by strength
        for (String mech : transformations.keySet()) {
            Arrays.sort(transformations.get(mech), new Comparator<TransformationSpec>() {
                @Override
                public int compare(TransformationSpec o1, TransformationSpec o2) {
                    if (o1.getStrength() < o2.getStrength()) {
                        return 1;
                    } else if (o1.getStrength() > o2.getStrength()) {
                        return -1;
                    } else {
                        return 0;
                    }
                }
            });
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see org.wildfly.security.util.TransformationMapper#getTransformationSpec(java.lang.String, java.lang.String)
     */
    @Override
    public TransformationSpec getTransformationSpec(String mechanism, String token) throws IllegalArgumentException {
        return getTransformationSpec(null, mechanism, token);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.wildfly.security.util.TransformationMapper#getTransformationSpec(java.lang.String, java.lang.String,
     * java.lang.String)
     */
    @Override
    public TransformationSpec getTransformationSpec(String provider, String mechanism, String token)
            throws IllegalArgumentException {
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        TransformationSpec[] ts = transformations.get(mechanism);
        if (ts == null) {
            throw new IllegalArgumentException(String.format("Mechanism %s not supported.", mechanism));
        }
        for (TransformationSpec t : ts) {
            if (token.equals(t.getToken()) && (provider == null || provider.equals(t.getProvider()))) {
                return t;
            }
        }
        return null;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.wildfly.security.util.TransformationMapper#getTransformationSpecByStrength(java.lang.String, java.lang.String[])
     */
    @Override
    public TransformationSpec[] getTransformationSpecByStrength(String mechanism, String... tokens)
            throws IllegalArgumentException {
        return getTransformationSpecByStrength(null, mechanism, tokens);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.wildfly.security.util.TransformationMapper#getTransformationSpecByStrength(java.lang.String, java.lang.String,
     * java.lang.String[])
     */
    @Override
    public TransformationSpec[] getTransformationSpecByStrength(String provider, String mechanism, String... tokens)
            throws IllegalArgumentException {

        if (tokens == null) {
            throw new IllegalArgumentException("Tokens need to be specified");
        }
        TransformationSpec[] ts = transformations.get(mechanism);
        if (ts == null) {
            throw new IllegalArgumentException(String.format("Mechanism %s not supported.", mechanism));
        }

        ArrayList<TransformationSpec> tf = new ArrayList<TransformationSpec>(ts.length);

        for (TransformationSpec t : ts) {
            for (String token : tokens) {
                if (token.equals(t.getToken()) && (provider == null || provider.equals(t.getProvider()))) {
                    tf.add(t);
                }
            }
        }
        return tf.toArray(new TransformationSpec[tf.size()]);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.wildfly.security.util.TransformationMapper#getTransformationSpecWithStrength(java.lang.String, int,
     * java.lang.String[])
     */
    @Override
    public TransformationSpec[] getTransformationSpecWithStrength(String mechanism, int strength, String... tokens)
            throws IllegalArgumentException {
        return getTransformationSpecWithStrength(null, mechanism, strength, tokens);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.wildfly.security.util.TransformationMapper#getTransformationSpecWithStrength(java.lang.String, java.lang.String,
     * int, java.lang.String[])
     */
    @Override
    public TransformationSpec[] getTransformationSpecWithStrength(String provider, String mechanism, int strength,
            String... tokens) throws IllegalArgumentException {

        if (tokens == null) {
            throw new IllegalArgumentException("Tokens need to be specified");
        }
        TransformationSpec[] ts = transformations.get(mechanism);
        if (ts == null) {
            throw new IllegalArgumentException(String.format("Mechanism %s not supported.", mechanism));
        }

        ArrayList<TransformationSpec> tf = new ArrayList<TransformationSpec>(ts.length);

        for (TransformationSpec t : ts) {
            for (String token : tokens) {
                if (token.equals(t.getToken())
                        && (provider == null || provider.equals(t.getProvider()) && (strength <= t.getStrength()))) {
                    tf.add(t);
                }
            }
        }
        return tf.toArray(new TransformationSpec[tf.size()]);
    }

}
