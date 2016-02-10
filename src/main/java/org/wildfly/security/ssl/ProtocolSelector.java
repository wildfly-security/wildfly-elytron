/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.ssl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * An immutable filter for SSL/TLS protocols.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class ProtocolSelector {

    final ProtocolSelector prev;

    ProtocolSelector(final ProtocolSelector prev) {
        this.prev = prev;
    }

    /* -- predicates -- */

    private static final ProtocolSelector EMPTY = new ProtocolSelector(null) {
        void applyFilter(final Set<Protocol> enabled, final EnumMap<Protocol, String> supported) {
        }

        void toString(final StringBuilder b) {
            b.append("(empty)");
        }
    };

    public final String toString() {
        final StringBuilder b = new StringBuilder();
        toString(b);
        return b.toString();
    }

    abstract void toString(final StringBuilder b);

    /**
     * Get the basic empty SSL protocol selector.
     *
     * @return the empty selector
     */
    public static ProtocolSelector empty() {
        return EMPTY;
    }

    /**
     * Get the default SSL protocol selector.
     *
     * @return the default selector
     */
    public static ProtocolSelector defaultProtocols() {
        return DEFAULT_SELECTOR;
    }


    /* -- Put this after the EMPTY selector for proper static ordering -- */
    static final ProtocolSelector DEFAULT_SELECTOR = empty().add(Protocol.TLSv1, Protocol.TLSv1_1, Protocol.TLSv1_2, Protocol.TLSv1_3);


    /* -- delete -- */

    /**
     * Permanently delete the given protocol.  Matching protocols cannot
     * be re-added by a later rule (such rules will be ignored).
     *
     * @param protocolName the name of the protocol to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector deleteFully(final String protocolName) {
        return deleteFully(Protocol.forName(protocolName));
    }

    /**
     * Permanently delete the given protocol.  Matching protocols cannot
     * be re-added by a later rule (such rules will be ignored).
     *
     * @param protocol the protocol to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector deleteFully(final Protocol protocol) {
        return protocol == null ? this : new FullyDeletingProtocolSelector(this, EnumSet.of(protocol));
    }

    /**
     * Permanently delete all of the given protocols.  Matching protocols cannot
     * be re-added by a later rule (such rules will be ignored).
     *
     * @param protocols the protocols to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector deleteFully(final Protocol... protocols) {
        return protocols == null || protocols.length == 0 ? this : new FullyDeletingProtocolSelector(this, EnumSet.of(protocols[0], protocols));
    }

    /**
     * Permanently delete all of the given protocols.  Matching protocols cannot
     * be re-added by a later rule (such rules will be ignored).
     *
     * @param protocols the protocols to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector deleteFully(final EnumSet<Protocol> protocols) {
        return protocols == null || protocols.isEmpty() ? this : new FullyDeletingProtocolSelector(this, protocols);
    }

    /* -- remove -- */

    /**
     * Remove the given protocol.  Matching protocols may be re-added by a later rule.
     *
     * @param protocolName the name of the protocol to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector remove(final String protocolName) {
        return remove(Protocol.forName(protocolName));
    }

    /**
     * Remove the given protocol.  Matching protocols may be re-added by a later rule.
     *
     * @param protocol the protocol to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector remove(final Protocol protocol) {
        return protocol == null ? this : new RemovingProtocolSelector(this, EnumSet.of(protocol));
    }

    /**
     * Remove the given protocols.  Matching protocols may be re-added by a later rule.
     *
     * @param protocols the protocols to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector remove(final Protocol... protocols) {
        return protocols == null || protocols.length == 0 ? this : new RemovingProtocolSelector(this, EnumSet.of(protocols[0], protocols));
    }

    /**
     * Remove the given protocols.  Matching protocols may be re-added by a later rule.
     *
     * @param protocols the protocols to remove
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector remove(final EnumSet<Protocol> protocols) {
        return protocols == null || protocols.isEmpty() ? this : new RemovingProtocolSelector(this, protocols);
    }

    /* -- add -- */

    /**
     * Add the given protocol.
     *
     * @param protocolName the name of the protocol to add
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector add(final String protocolName) {
        return add(Protocol.forName(protocolName));
    }

    /**
     * Add the given protocol.
     *
     * @param protocol the protocol to add
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector add(final Protocol protocol) {
        return protocol == null ? this : new AddingProtocolSelector(this, EnumSet.of(protocol));
    }

    /**
     * Add the given protocols.
     *
     * @param protocols the protocols to add
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector add(final Protocol... protocols) {
        return protocols == null || protocols.length == 0 ? this : new AddingProtocolSelector(this, EnumSet.of(protocols[0], protocols));
    }

    /**
     * Add the given protocols.
     *
     * @param protocols the protocols to add
     * @return a new selector which includes the new rule
     */
    public ProtocolSelector add(final EnumSet<Protocol> protocols) {
        return protocols == null || protocols.isEmpty() ? this : new AddingProtocolSelector(this, protocols);
    }

    /* -- selector implementation -- */

    abstract void applyFilter(Set<Protocol> enabled, EnumMap<Protocol, String> supported);

    private void doEvaluate(Set<Protocol> enabled, EnumMap<Protocol, String> supported) {
        if (prev != null) {
            prev.doEvaluate(enabled, supported);
        }
        applyFilter(enabled, supported);
    }

    /**
     * Evaluate this selector against the given list of JSSE supported protocols.
     *
     * @param supportedProtocols the supported protocols
     * @return the enabled protocols (not {@code null})
     */
    public final String[] evaluate(String[] supportedProtocols) {
        final EnumMap<Protocol, String> supported = new EnumMap<Protocol, String>(Protocol.class);
        for (String protocolName : supportedProtocols) {
            final Protocol protocol = Protocol.forName(protocolName);
            if (protocol != null) {
                supported.put(protocol, protocolName);
            }
        }
        final LinkedHashSet<Protocol> enabledSet = new LinkedHashSet<>(supported.size());
        doEvaluate(enabledSet, supported);
        final ArrayList<String> list = new ArrayList<>(enabledSet.size());
        for (Protocol protocol : enabledSet) {
            list.add(supported.get(protocol));
        }
        return list.toArray(new String[enabledSet.size()]);
    }

    /* -- selector impls -- */

    static final class AddingProtocolSelector extends ProtocolSelector {
        private final EnumSet<Protocol> protocols;

        AddingProtocolSelector(final ProtocolSelector prev, final EnumSet<Protocol> protocols) {
            super(prev);
            this.protocols = protocols;
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("add protocols (");
            Iterator<Protocol> iterator = protocols.iterator();
            Protocol protocol;
            if (iterator.hasNext()) {
                protocol = iterator.next();
                b.append(protocol);
                while (iterator.hasNext()) {
                    b.append(", ");
                    b.append(protocol);
                }
            }
            b.append(")");
        }

        void applyFilter(final Set<Protocol> enabled, final EnumMap<Protocol, String> supported) {
            final List<Protocol> clone = new ArrayList<>(supported.keySet());
            clone.retainAll(protocols);
            // it will be in reverse-preference order due to the ordering of the enum
            Collections.reverse(clone);
            enabled.addAll(clone);
        }
    }

    static final class RemovingProtocolSelector extends ProtocolSelector {
        private final EnumSet<Protocol> protocols;

        RemovingProtocolSelector(final ProtocolSelector prev, final EnumSet<Protocol> protocols) {
            super(prev);
            this.protocols = protocols;
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("remove protocols (");
            Iterator<Protocol> iterator = protocols.iterator();
            Protocol protocol;
            if (iterator.hasNext()) {
                protocol = iterator.next();
                b.append(protocol);
                while (iterator.hasNext()) {
                    b.append(", ");
                    b.append(protocol);
                }
            }
            b.append(")");
        }

        void applyFilter(final Set<Protocol> enabled, final EnumMap<Protocol, String> supported) {
            enabled.remove(protocols);
        }
    }

    static class FullyDeletingProtocolSelector extends ProtocolSelector {
        private final EnumSet<Protocol> protocols;

        FullyDeletingProtocolSelector(final ProtocolSelector prev, final EnumSet<Protocol> protocols) {
            super(prev);
            this.protocols = protocols;
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("fully remove protocols (");
            Iterator<Protocol> iterator = protocols.iterator();
            Protocol protocol;
            if (iterator.hasNext()) {
                protocol = iterator.next();
                b.append(protocol);
                while (iterator.hasNext()) {
                    b.append(", ");
                    b.append(protocol);
                }
            }
            b.append(")");
        }

        void applyFilter(final Set<Protocol> enabled, final EnumMap<Protocol, String> supported) {
            enabled.removeAll(protocols);
            for (Protocol protocol : protocols) {
                supported.remove(protocol);
            }
        }
    }
}
