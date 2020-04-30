/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.authz;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;


/**
 * An implementation of {@link Attributes} aggregating multiple instances.
 *
 * Attributes are aggregated on a 'first defined wins' basis, i.e. the first definition of a specific attribute is the one used and remaining definitions are discarded.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AggregateAttributes implements Attributes {

    private final Map<String, Entry> aggregatedEntries;

    private AggregateAttributes(final Attributes[] aggrgatedAttributes) {
        Map<String, Entry> aggregatedEntries = new HashMap<>();
        for (Attributes currentAttributes : aggrgatedAttributes) {
            for (Entry currentEntry : currentAttributes.entries()) {
                String key = currentEntry.getKey();
                if (aggregatedEntries.containsKey(key) == false) {
                    aggregatedEntries.put(key, currentEntry);
                }
            }
        }
        this.aggregatedEntries = aggregatedEntries;
    }

    public static Attributes aggregateOf(Attributes... aggrgatedAttributes) {
        return new AggregateAttributes(aggrgatedAttributes)
                .asReadOnly();
    }

    @Override
    public Collection<Entry> entries() {
        return aggregatedEntries.values();
    }

    @Override
    public int size(String key) {
        return get(key).size();
    }

    @Override
    public Entry get(String key) {
        if (aggregatedEntries.containsKey(key)) {
            return aggregatedEntries.get(key);
        }

        // We don't know about this attribute key and can't add it to any of the aggreagted entries.
        return new SimpleAttributesEntry(Attributes.EMPTY, key);
    }

    @Override
    public String get(String key, int idx) {
        return get(key).get(idx);
    }

    @Override
    public int size() {
        return entries().size();
    }

}
