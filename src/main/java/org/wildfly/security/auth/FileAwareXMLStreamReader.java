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

import static org.wildfly.security.auth.XMLLocation.toXMLLocation;

import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.stream.Location;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class FileAwareXMLStreamReader implements XMLStreamReader {
    private final XMLStreamReader streamReader;
    private final String fileName;

    FileAwareXMLStreamReader(final XMLStreamReader streamReader, final String fileName) {
        this.streamReader = streamReader;
        this.fileName = fileName;
    }

    static FileAwareXMLStreamReader from(XMLStreamReader reader) {
        return reader instanceof FileAwareXMLStreamReader ? (FileAwareXMLStreamReader) reader : new FileAwareXMLStreamReader(reader, null);
    }

    static FileAwareXMLStreamReader from(final XMLStreamReader reader, final String fileName) {
        return reader instanceof FileAwareXMLStreamReader ? (FileAwareXMLStreamReader) reader : new FileAwareXMLStreamReader(reader, fileName);
    }

    public Object getProperty(final String name) throws IllegalArgumentException {
        return streamReader.getProperty(name);
    }

    public int next() throws XMLStreamException {
        try {
            return streamReader.next();
        } catch (XMLStreamException ex) {
            throw ElytronXMLParseException.from(ex, fileName);
        }
    }

    public void require(final int type, final String namespaceURI, final String localName) throws XMLStreamException {
        try {
            streamReader.require(type, namespaceURI, localName);
        } catch (XMLStreamException ex) {
            throw ElytronXMLParseException.from(ex, fileName);
        }
    }

    public String getElementText() throws XMLStreamException {
        try {
            return streamReader.getElementText();
        } catch (XMLStreamException ex) {
            throw ElytronXMLParseException.from(ex, fileName);
        }
    }

    public int nextTag() throws XMLStreamException {
        try {
            return streamReader.nextTag();
        } catch (XMLStreamException ex) {
            throw ElytronXMLParseException.from(ex, fileName);
        }
    }

    public boolean hasNext() throws XMLStreamException {
        try {
            return streamReader.hasNext();
        } catch (XMLStreamException ex) {
            throw ElytronXMLParseException.from(ex, fileName);
        }
    }

    public void close() throws XMLStreamException {
        try {
            streamReader.close();
        } catch (XMLStreamException ex) {
            throw ElytronXMLParseException.from(ex, fileName);
        }
    }

    public String getNamespaceURI(final String prefix) {
        return streamReader.getNamespaceURI(prefix);
    }

    public boolean isStartElement() {
        return streamReader.isStartElement();
    }

    public boolean isEndElement() {
        return streamReader.isEndElement();
    }

    public boolean isCharacters() {
        return streamReader.isCharacters();
    }

    public boolean isWhiteSpace() {
        return streamReader.isWhiteSpace();
    }

    public String getAttributeValue(final String namespaceURI, final String localName) {
        return streamReader.getAttributeValue(namespaceURI, localName);
    }

    public int getAttributeCount() {
        return streamReader.getAttributeCount();
    }

    public QName getAttributeName(final int index) {
        return streamReader.getAttributeName(index);
    }

    public String getAttributeNamespace(final int index) {
        return streamReader.getAttributeNamespace(index);
    }

    public String getAttributeLocalName(final int index) {
        return streamReader.getAttributeLocalName(index);
    }

    public String getAttributePrefix(final int index) {
        return streamReader.getAttributePrefix(index);
    }

    public String getAttributeType(final int index) {
        return streamReader.getAttributeType(index);
    }

    public String getAttributeValue(final int index) {
        return streamReader.getAttributeValue(index);
    }

    public boolean isAttributeSpecified(final int index) {
        return streamReader.isAttributeSpecified(index);
    }

    public int getNamespaceCount() {
        return streamReader.getNamespaceCount();
    }

    public String getNamespacePrefix(final int index) {
        return streamReader.getNamespacePrefix(index);
    }

    public String getNamespaceURI(final int index) {
        return streamReader.getNamespaceURI(index);
    }

    public NamespaceContext getNamespaceContext() {
        return streamReader.getNamespaceContext();
    }

    public int getEventType() {
        return streamReader.getEventType();
    }

    public String getText() {
        return streamReader.getText();
    }

    public char[] getTextCharacters() {
        return streamReader.getTextCharacters();
    }

    public int getTextCharacters(final int sourceStart, final char[] target, final int targetStart, final int length) throws XMLStreamException {
        try {
            return streamReader.getTextCharacters(sourceStart, target, targetStart, length);
        } catch (XMLStreamException ex) {
            throw ElytronXMLParseException.from(ex, fileName);
        }
    }

    public int getTextStart() {
        return streamReader.getTextStart();
    }

    public int getTextLength() {
        return streamReader.getTextLength();
    }

    public String getEncoding() {
        return streamReader.getEncoding();
    }

    public boolean hasText() {
        return streamReader.hasText();
    }

    public Location getLocation() {
        return toXMLLocation(streamReader.getLocation());
    }

    public QName getName() {
        return streamReader.getName();
    }

    public String getLocalName() {
        return streamReader.getLocalName();
    }

    public boolean hasName() {
        return streamReader.hasName();
    }

    public String getNamespaceURI() {
        return streamReader.getNamespaceURI();
    }

    public String getPrefix() {
        return streamReader.getPrefix();
    }

    public String getVersion() {
        return streamReader.getVersion();
    }

    public boolean isStandalone() {
        return streamReader.isStandalone();
    }

    public boolean standaloneSet() {
        return streamReader.standaloneSet();
    }

    public String getCharacterEncodingScheme() {
        return streamReader.getCharacterEncodingScheme();
    }

    public String getPITarget() {
        return streamReader.getPITarget();
    }

    public String getPIData() {
        return streamReader.getPIData();
    }
}
