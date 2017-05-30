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

package org.wildfly.security.util;

import static org.wildfly.security._private.ElytronMessages.log;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * Utilities for URI manipulation and canonicalization.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class URIUtil {
    private URIUtil() {}

    /**
     * Get the URI-friendly host name for the given socket address, without doing a reverse lookup under any circumstances.
     *
     * @param socketAddress the destination socket address
     * @return the URI host string
     */
    public static String getHostForURI(SocketAddress socketAddress) {
        if (socketAddress instanceof InetSocketAddress) {
            final InetSocketAddress inetSocketAddress = (InetSocketAddress) socketAddress;
            final String hostString = inetSocketAddress.getHostString();
            final InetAddress address = inetSocketAddress.getAddress();
            if (address instanceof Inet6Address && hostString != null && address != null && hostString.equals(address.getHostAddress())) {
                return "[" + address.getHostAddress() + "]";
            } else {
                return hostString;
            }
        }
        throw log.invalidSocketAddressTypeForUri();
    }

    /**
     * Get the port number for the given socket address.  If the port number matches the given default port, then -1
     * is returned to allow the URI to use the default value.
     *
     * @param socketAddress the destination socket address
     * @param defaultPort the default port number for the URI scheme, or -1 if there is none or it is unknown
     * @return the URI port number
     */
    public static int getPortForURI(SocketAddress socketAddress, int defaultPort) {
        if (socketAddress instanceof InetSocketAddress) {
            final InetSocketAddress inetSocketAddress = (InetSocketAddress) socketAddress;
            final int port = inetSocketAddress.getPort();
            if (port == defaultPort) {
                return -1;
            } else {
                return port;
            }
        }
        throw log.invalidSocketAddressTypeForUri();
    }

    /**
     * Create a URI from a socket address and additional information.
     *
     * @param scheme the URI scheme
     * @param socketAddress the destination socket address
     * @param defaultPort the scheme default port, or -1 if there is no standard default port
     * @return the URI
     * @throws URISyntaxException if the URI construction failed for some reason
     */
    public static URI createURI(String scheme, SocketAddress socketAddress, int defaultPort) throws URISyntaxException {
        return new URI(scheme, null, getHostForURI(socketAddress), getPortForURI(socketAddress, defaultPort), null, null, null);
    }

    /**
     * Create a URI from a socket address and additional information.
     *
     * @param scheme the URI scheme
     * @param socketAddress the destination socket address
     * @return the URI
     * @throws URISyntaxException if the URI construction failed for some reason
     */
    public static URI createURI(String scheme, SocketAddress socketAddress) throws URISyntaxException {
        return createURI(scheme, socketAddress, -1);
    }

    /**
     * Get the user name information from a URI, if any.
     *
     * @param uri the URI
     * @return the user name, or {@code null} if the URI did not contain a recoverable user name
     */
    public static String getUserFromURI(URI uri) {
        String userInfo = uri.getUserInfo();
        if (userInfo == null && "domain".equals(uri.getScheme())) {
            final String ssp = uri.getSchemeSpecificPart();
            final int at = ssp.lastIndexOf('@');
            if (at == -1) {
                return null;
            }
            userInfo = ssp.substring(0, at);
        }
        if (userInfo != null) {
            final int colon = userInfo.indexOf(':');
            if (colon != -1) {
                userInfo = userInfo.substring(0, colon);
            }
        }
        return userInfo;
    }

    /**
     * Get an Internet address for a URI destination, resolving the host name if necessary.
     *
     * @param uri the destination URI
     * @return the socket address, or {@code null} if no authority is present in the URI
     * @throws UnknownHostException if the URI host was existent but could not be resolved to a valid address
     */
    public static InetAddress getDestinationInetAddress(URI uri) throws UnknownHostException {
        final String host = uri.getHost();
        if (host == null) {
            return null;
        }
        final int length = host.length();
        if (length == 0) {
            return null;
        }
        return InetAddress.getByName(host);
    }

    /**
     * Get a socket address for a URI destination, resolving the host name if necessary.  If the host name could not
     * be resolved, an {@linkplain InetSocketAddress#isUnresolved() unresolved} address is returned.
     *
     * @param uri the destination URI
     * @param defaultPort the default port number for the URI scheme, or -1 if there is none or it is unknown
     * @return the socket address, or {@code null} if no authority is present in the URI or no port number could be determined
     */
    public static InetSocketAddress getDestinationInetSocketAddress(URI uri, int defaultPort) {
        final String host = uri.getHost();
        if (host == null) {
            return null;
        }
        final int length = host.length();
        if (length == 0) {
            return null;
        }
        int port = uri.getPort();
        if (port == -1) port = defaultPort;
        if (port == -1) {
            return null;
        }
        return new InetSocketAddress(host, port);
    }
}
