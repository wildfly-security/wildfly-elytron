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

package org.wildfly.security.auth;

import static org.wildfly.security._private.ElytronMessages.log;

import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class ElytronXMLParseException extends XMLStreamException {

    private static final long serialVersionUID = -1880381457871462141L;

    /**
     * Constructs a new {@code ElytronXMLParseException} instance.  The message is left blank ({@code null}), and no
     * cause is specified.
     */
    public ElytronXMLParseException() {
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     */
    public ElytronXMLParseException(final String msg) {
        super(msg);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial cause.  If a non-{@code null} cause is
     * specified, its message is used to initialize the message of this {@code ElytronXMLParseException}; otherwise the
     * message is left blank ({@code null}).
     *
     * @param cause the cause
     */
    public ElytronXMLParseException(final Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param cause the cause
     */
    public ElytronXMLParseException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance.  The message is left blank ({@code null}), and no
     * cause is specified.
     *
     * @param location the location of the exception
     */
    public ElytronXMLParseException(final Location location) {
        this(log.parseError(), XMLLocation.toXMLLocation(location), 0);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     * @param location the location of the exception
     */
    public ElytronXMLParseException(final String msg, final Location location) {
        this(msg, XMLLocation.toXMLLocation(location), 0);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial cause.  If a non-{@code null} cause is
     * specified, its message is used to initialize the message of this {@code ElytronXMLParseException}; otherwise the
     * message is left blank ({@code null}).
     *
     * @param cause the cause
     * @param location the location of the exception
     */
    public ElytronXMLParseException(final Throwable cause, final Location location) {
        this(log.parseError(), XMLLocation.toXMLLocation(location), cause, 0);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial message and cause.
     *  @param msg the message
     * @param location the location of the exception
     * @param cause the cause
     */
    public ElytronXMLParseException(final String msg, final Location location, final Throwable cause) {
        this(msg, XMLLocation.toXMLLocation(location), cause, 0);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance.  The message is left blank ({@code null}), and no
     * cause is specified.
     *
     * @param reader an XML reader at the position of the problem
     */
    public ElytronXMLParseException(final XMLStreamReader reader) {
        this(log.parseError(), XMLLocation.toXMLLocation(reader.getLocation()), 0);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial message.  No cause is specified.
     *
     * @param msg the message
     * @param reader an XML reader at the position of the problem
     */
    public ElytronXMLParseException(final String msg, final XMLStreamReader reader) {
        this(msg, XMLLocation.toXMLLocation(reader.getLocation()), 0);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial cause.  If a non-{@code null} cause is
     * specified, its message is used to initialize the message of this {@code ElytronXMLParseException}; otherwise the
     * message is left blank ({@code null}).
     *
     * @param cause the cause
     * @param reader an XML reader at the position of the problem
     */
    public ElytronXMLParseException(final Throwable cause, final XMLStreamReader reader) {
        this(log.parseError(), XMLLocation.toXMLLocation(reader.getLocation()), cause, 0);
    }

    /**
     * Constructs a new {@code ElytronXMLParseException} instance with an initial message and cause.
     *
     * @param msg the message
     * @param reader an XML reader at the position of the problem
     * @param cause the cause
     */
    public ElytronXMLParseException(final String msg, final XMLStreamReader reader, final Throwable cause) {
        this(msg, XMLLocation.toXMLLocation(reader.getLocation()), cause, 0);
    }

    static ElytronXMLParseException from(final XMLStreamException exception) {
        if (exception instanceof ElytronXMLParseException) return (ElytronXMLParseException) exception;
        final Throwable cause = exception.getCause();
        if (cause != null) {
            return new ElytronXMLParseException(clean(exception.getMessage()), exception.getLocation(), cause);
        } else {
            return new ElytronXMLParseException(clean(exception.getMessage()), exception.getLocation());
        }
    }

    static ElytronXMLParseException from(final XMLStreamException exception, final String fileName) {
        if (exception instanceof ElytronXMLParseException) return (ElytronXMLParseException) exception;
        final Throwable cause = exception.getCause();
        if (cause != null) {
            return new ElytronXMLParseException(clean(exception.getMessage()), XMLLocation.toXMLLocation(fileName, exception.getLocation()), cause);
        } else {
            return new ElytronXMLParseException(clean(exception.getMessage()), XMLLocation.toXMLLocation(fileName, exception.getLocation()));
        }
    }

    private static String clean(String original) {
        if (original.startsWith("ParseError at [row,col]:[")) {
            final int idx = original.indexOf("Message: ");
            return idx == -1 ? original : original.substring(idx + 9);
        } else {
            return original;
        }
    }

    private ElytronXMLParseException(final String msg, final XMLLocation location, @SuppressWarnings("unused") int ignored) {
        super(formatted(msg, location));
        this.location = location;
    }

    private ElytronXMLParseException(final String msg, final XMLLocation location, final Throwable cause, @SuppressWarnings("unused") int ignored) {
        super(formatted(msg, location), cause);
        this.location = location;
    }

    private static String formatted(String msg, Location location) {
        return String.format("%s <%s>", msg, location);
    }
}
