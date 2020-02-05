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

package org.wildfly.security.auth.client;

import static org.wildfly.security.auth.client._private.ElytronMessages.log;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;

import org.wildfly.common.net.CidrAddress;
import org.wildfly.common.net.Inet;

/**
 * A rule used for deciding which authentication configuration to use.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class MatchRule {

    private final MatchRule parent;

    /**
     * The root rule which matches all URIs.
     */
    public static final MatchRule ALL = new MatchRule(null) {

        @Override
        MatchRule reparent(final MatchRule newParent) {
            return this;
        }

        @Override
        public boolean isProtocolMatched() {
            return false;
        }

        @Override
        public boolean isTypeMatched() {
            return false;
        }

        @Override
        public boolean isTypeAuthorityMatched() {
            return false;
        }

        @Override
        public String getMatchProtocol() {
            return null;
        }

        @Override
        public String getMatchAbstractType() {
            return null;
        }

        @Override
        public String getMatchAbstractTypeAuthority() {
            return null;
        }

        @Override
        public boolean isHostMatched() {
            return false;
        }

        @Override
        public String getMatchHost() {
            return null;
        }

        @Override
        public boolean isPathMatched() {
            return false;
        }

        @Override
        public String getMatchPath() {
            return null;
        }

        @Override
        public boolean isPortMatched() {
            return false;
        }

        @Override
        public int getMatchPort() {
            return 0;
        }

        @Override
        public boolean isUserMatched() {
            return true;
        }

        @Override
        public String getMatchUser() {
            return null;
        }

        @Override
        public boolean isUrnNameMatched() {
            return false;
        }

        @Override
        public String getMatchUrnName() {
            return null;
        }

        @Override
        public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority) {
            return true;
        }

        @Override
        MatchRule without(final Class<? extends MatchRule> clazz) {
            return this;
        }

        @Override
        boolean halfEqual(final MatchRule other) {
            return true;
        }

        @Override
        public int hashCode() {
            return System.identityHashCode(this);
        }

        @Override
        StringBuilder asString(final StringBuilder b) {
            return b;
        }
    };

    MatchRule(final MatchRule parent) {
        this.parent = parent;
    }

    abstract MatchRule reparent(MatchRule newParent);

    /**
     * Determine whether this rule is equal to another object.  Two rules are equal if they match the same conditions.
     *
     * @param other the other object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public final boolean equals(final Object other) {
        return other instanceof MatchRule && equals((MatchRule) other);
    }

    /**
     * Determine whether this rule is equal to another.  Two rules are equal if they match the same conditions.
     *
     * @param other the other object
     * @return {@code true} if they are equal, {@code false} otherwise
     */
    public final boolean equals(MatchRule other) {
        return hashCode() == other.hashCode() && halfEqual(other) && other.halfEqual(this);
    }

    abstract boolean halfEqual(MatchRule other);

    final boolean parentHalfEqual(MatchRule other) {
        return parent.halfEqual(other);
    }

    /**
     * Get the hash code of this rule.
     *
     * @return the hash code
     */
    public abstract int hashCode();

    final int parentHashCode() {
        return parent.hashCode();
    }

    MatchRule without(Class<? extends MatchRule> clazz) {
        if (clazz.isInstance(this)) return parent;
        MatchRule newParent = parent.without(clazz);
        if (parent == newParent) return this;
        return reparent(newParent);
    }

    /**
     * Determine if this rule matches the given URI.
     *
     * @param uri the URI to test
     * @return {@code true} if the rule matches, {@code false} otherwise
     */
    public final boolean matches(URI uri) {
        return matches(uri, null, null);
    }

    /**
     * Determine if this rule matches the given URI, and type.
     *
     * @param uri the URI to test
     * @param abstractType the abstract type of the connection (may be {@code null})
     * @param abstractTypeAuthority the authority name of the abstract type (may be {@code null})
     * @return {@code true} if the rule matches, {@code false} otherwise
     */
    public boolean matches(URI uri, final String abstractType, final String abstractTypeAuthority) {
        return parent.matches(uri, abstractType, abstractTypeAuthority);
    }

    // protocol (scheme)

    /**
     * Determine whether this rule matches based on URI protocol (scheme).
     *
     * @return {@code true} if the rule matches based on URI protocol, {@code false} otherwise
     */
    public boolean isProtocolMatched() {
        return parent.isProtocolMatched();
    }

    /**
     * Get the protocol (scheme) that this rule matches, or {@code null} if this rule does not match by protocol.
     *
     * @return the protocol, or {@code null} if there is none
     */
    public String getMatchProtocol() {
        return parent.getMatchProtocol();
    }

    /**
     * Determine whether this rule matches based on abstract type.
     *
     * @return {@code true} if the rule matches based on type, {@code false} otherwise
     */
    public boolean isTypeMatched() {
        return parent.isTypeMatched();
    }

    /**
     * Determine whether this rule matches based on abstract type.
     *
     * @return {@code true} if the rule matches based on type, {@code false} otherwise
     */
    public boolean isTypeAuthorityMatched() {
        return parent.isTypeAuthorityMatched();
    }

    /**
     * Get the abstract type that this rule matches, or {@code null} if this rule does not match by abstract type.
     *
     * @return the abstract type, or {@code null} if there is none
     */
    public String getMatchAbstractType() {
        return parent.getMatchAbstractType();
    }

    /**
     * Get the abstract type authority that this rule matches, or {@code null} if this rule does not match by abstract type authority.
     *
     * @return the abstract type, or {@code null} if there is none
     */
    public String getMatchAbstractTypeAuthority() {
        return parent.getMatchAbstractTypeAuthority();
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given protocol (scheme) name.
     *
     * @param protoName the protocol name to match
     * @return the new rule
     */
    public final MatchRule matchProtocol(String protoName) {
        if (protoName == null || protoName.equals("*")) {
            return without(MatchSchemeRule.class);
        }
        return new MatchSchemeRule(this, protoName);
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given abstract type and type authority.
     *
     * @param typeName the type to match
     * @param authorityName the type authority name to match
     * @return the new rule
     */
    public final MatchRule matchAbstractType(String typeName, String authorityName) {
        MatchRule baseRule;
        if (typeName == null || typeName.equals("*")) {
            baseRule = without(MatchAbstractTypeRule.class);
        } else {
            baseRule = new MatchAbstractTypeRule(this, typeName);
        }
        if (authorityName == null || authorityName.equals("*")) {
            return baseRule.without(MatchAbstractTypeAuthorityRule.class);
        } else {
            return new MatchAbstractTypeAuthorityRule(baseRule, authorityName);
        }
    }

    // host

    /**
     * Determine whether this rule matches based on host name.
     *
     * @return {@code true} if the rule matches based on host name, {@code false} otherwise
     */
    public boolean isHostMatched() {
        return parent.isHostMatched();
    }

    /**
     * Get the host name that this rule matches, or {@code null} if this rule does not match by host.
     *
     * @return the host name, or {@code null} if there is none
     */
    public String getMatchHost() {
        return parent.getMatchHost();
    }

    /**
     * Determine whether this rule matches based on network.
     *
     * @return {@code true} if the rule matches based on network, {@code false} otherwise
     */
    public boolean isNetworkMatched() {
        return parent.isNetworkMatched();
    }

    /**
     * Get the network that this rule matches, or {@code null} if this rule does not match by network.
     *
     * @return the network that this rule matches, or {@code null} if there is none
     */
    public CidrAddress getMatchNetwork() {
        return parent.getMatchNetwork();
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given host name.  If the given string
     * appears to be an IP address or a CIDR network specification, then it is treated as such.
     *
     * @param hostSpec the host name to match
     * @return the new rule
     */
    public final MatchRule matchHost(String hostSpec) {
        if (hostSpec == null || hostSpec.equals("*")) {
            return without(MatchHostRule.class).without(MatchNetworkRule.class);
        }
        final CidrAddress cidrAddress = Inet.parseCidrAddress(hostSpec);
        if (cidrAddress != null) {
            return new MatchNetworkRule(this, cidrAddress);
        }
        final InetAddress inetAddress = Inet.parseInetAddress(hostSpec);
        if (inetAddress != null) {
            return new MatchNetworkRule(this, CidrAddress.create(inetAddress, inetAddress instanceof Inet6Address ? 128 : 32));
        }
        return new MatchHostRule(this, hostSpec);
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given Internet address.
     *
     * @param inetAddress the address to match
     * @return the new rule
     */
    public final MatchRule matchAddress(InetAddress inetAddress) {
        if (inetAddress == null) {
            return without(MatchHostRule.class).without(MatchNetworkRule.class);
        } else {
            return new MatchNetworkRule(this, CidrAddress.create(inetAddress, inetAddress instanceof Inet6Address ? 128 : 32));
        }
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given Internet network address.
     *
     * @param cidrAddress the network to match
     * @return the new rule
     */
    public final MatchRule matchNetwork(CidrAddress cidrAddress) {
        if (cidrAddress == null) {
            return without(MatchHostRule.class).without(MatchNetworkRule.class);
        } else {
            return new MatchNetworkRule(this, cidrAddress);
        }
    }

    // path

    /**
     * Determine whether this rule matches based on path name.
     *
     * @return {@code true} if the rule matches based on path name, {@code false} otherwise
     */
    public boolean isPathMatched() {
        return parent.isPathMatched();
    }

    /**
     * Get the path name that this rule matches, or {@code null} if this rule does not match by path.
     *
     * @return the path name, or {@code null} if there is none
     */
    public String getMatchPath() {
        return parent.getMatchPath();
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given path name.
     *
     * @param pathSpec the path name to match
     * @return the new rule
     */
    public final MatchRule matchPath(String pathSpec) {
        if (pathSpec == null || pathSpec.equals("**") || pathSpec.equals("/**")) {
            return without(MatchPathRule.class);
        }
        return new MatchPathRule(this, pathSpec);
    }

    // port

    /**
     * Determine whether this rule matches based on port.
     *
     * @return {@code true} if the rule matches based on port, {@code false} otherwise
     */
    public boolean isPortMatched() {
        return parent.isPortMatched();
    }

    /**
     * Get the port number that this rule matches, or 0 if this rule does not match by port.
     *
     * @return the port number, or 0 if there is none
     */
    public int getMatchPort() {
        return parent.getMatchPort();
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given port number.  The port number must
     * be between 1 and 65535 (inclusive).
     *
     * @param port the port to match
     * @return the new rule
     */
    public final MatchRule matchPort(int port) {
        if (port <= 0 || port > 65535) {
            throw log.invalidPortNumber(port);
        }
        return new MatchPortRule(this, port);
    }

    // user

    // internal builder operations

    /**
     * Determine whether this rule matches based on non-empty URI user info.
     *
     * @return {@code true} if the rule matches based on non-empty user info, {@code false} otherwise
     */
    public boolean isUserMatched() {
        return parent.isUserMatched();
    }

    /**
     * Get the URI user info that this rule matches, or {@code null} if this rule only matches empty URI user info.
     *
     * @return the user info, or {@code null} if there is none
     */
    public String getMatchUser() {
        return parent.getMatchUser();
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given URI user info.
     *
     * @param userSpec the user info to match
     * @return the new rule
     */
    public final MatchRule matchUser(String userSpec) {
        return userSpec == null ? matchNoUser() : new MatchUserRule(this, userSpec);
    }

    /**
     * Create a new rule which is the same as this rule, but only matches URIs with no user info.
     *
     * @return the new rule
     */
    public final MatchRule matchNoUser() {
        return new MatchNoUserRule(this);
    }

    /**
     * Create a new rule which is the same as this rule, but matches URIs with or without user info.
     *
     * @return the new rule
     */
    public final MatchRule matchAnyUser() {
        return without(MatchUserRule.class).without(MatchNoUserRule.class);
    }

    // URN

    /**
     * Determine whether this rule matches based on URN name.
     *
     * @return {@code true} if the rule matches based on URN name, {@code false} otherwise
     */
    public boolean isUrnNameMatched() {
        return parent.isUrnNameMatched();
    }

    /**
     * Get the URN name that this rule matches, or {@code null} if this rule does not match by URN.
     *
     * @return the URN name, or {@code null} if there is none
     */
    public String getMatchUrnName() {
        return parent.getMatchUrnName();
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given URN name.
     *
     * @param name the URN name to match
     * @return the new rule
     */
    public final MatchRule matchUrnName(String name) {
        return name == null ? without(MatchSchemeSpecificPartRule.class) : new MatchSchemeSpecificPartRule(this, name);
    }

    /**
     * Create a new rule which is the same as this rule, but also matches the given security domain.
     *
     * @param name the security domain name to match
     * @return the new rule
     */
    public final MatchRule matchLocalSecurityDomain(String name) {
        return name == null ? matchProtocol(null).matchUrnName(null) : matchProtocol("domain").matchUrnName(name);
    }

    // string

    /**
     * Get the string representation of this rule.
     *
     * @return the string representation of this rule
     */
    public final String toString() {
        final StringBuilder b = new StringBuilder();
        asString(b);
        if (b.length() > 1) {
            b.setLength(b.length() - 1);
        }
        return b.toString();
    }

    final StringBuilder parentAsString(StringBuilder b) {
        return parent.asString(b);
    }

    abstract StringBuilder asString(StringBuilder b);
}
