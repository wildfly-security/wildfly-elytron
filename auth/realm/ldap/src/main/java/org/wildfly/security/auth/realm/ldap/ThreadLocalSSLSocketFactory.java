/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm.ldap;

import static org.wildfly.security.auth.realm.ldap.ElytronMessages.log;

import javax.net.SocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * An {@link javax.net.SocketFactory} that allow passing SSLSocket into DirContext.
 *
 * DirContext allows SocketFactory passing only in form of class name string, which prevent
 * to pass different SSL configuration into different DirContexts without standalone classes.
 *
 * This socket factory bypass this using thread local variable with SocketFactory,
 * which should be used in directly following socket-creating DirContext operation.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class ThreadLocalSSLSocketFactory extends SocketFactory {

    private static final ThreadLocal<SocketFactory> threadLocal = new ThreadLocal<>();

    public static SocketFactory getDefault() {
        SocketFactory socketFactory = threadLocal.get();
        if (socketFactory == null) {
            throw log.threadLocalSslSocketFactoryThreadLocalNotSet();
        }
        return socketFactory;
    }

    public static void set(SocketFactory socketFactory) {
        threadLocal.set(new ThreadLocalSSLSocketFactory(socketFactory));
    }

    public static void unset() {
        threadLocal.remove();
    }

    // non-static part

    private SocketFactory socketFactory; // delegation required by com.sun.jndi.ldap.Connection

    private ThreadLocalSSLSocketFactory(SocketFactory socketFactory) {
        this.socketFactory = socketFactory;
    }

    @Override
    public Socket createSocket() throws IOException {
        return socketFactory.createSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return socketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return socketFactory.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return socketFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return socketFactory.createSocket(address, port, localAddress, localPort);
    }
}
