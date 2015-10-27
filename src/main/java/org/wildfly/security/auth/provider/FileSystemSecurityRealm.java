/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.provider;

import static java.nio.file.StandardOpenOption.*;
import static javax.xml.stream.XMLStreamConstants.*;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ThreadLocalRandom;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.BasicPasswordSpecEncoding;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.util.ModularCrypt;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;

/**
 * A simple filesystem-backed security realm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class FileSystemSecurityRealm implements ModifiableSecurityRealm {

    static final String ELYTRON_1_0 = "urn:elytron:1.0";

    private final Path root;
    private final NameRewriter nameRewriter;
    private final int levels;

    /**
     * Construct a new instance.
     *
     * @param root the root path of the identity store
     * @param nameRewriter the name rewriter to apply to looked up names
     * @param levels the number of levels of directory hashing to apply
     */
    public FileSystemSecurityRealm(final Path root, final NameRewriter nameRewriter, final int levels) {
        this.root = root;
        this.nameRewriter = nameRewriter;
        this.levels = levels;
    }

    /**
     * Construct a new instance.
     *
     * @param root the root path of the identity store
     * @param levels the number of levels of directory hashing to apply
     */
    public FileSystemSecurityRealm(final Path root, final int levels) {
        this.root = root;
        this.levels = levels;
        nameRewriter = NameRewriter.IDENTITY_REWRITER;
    }

    /**
     * Construct a new instance with 2 levels of hashing.
     *
     * @param root the root path of the identity store
     */
    public FileSystemSecurityRealm(final Path root) {
        this.root = root;
        levels = 2;
        nameRewriter = NameRewriter.IDENTITY_REWRITER;
    }

    private Path pathFor(final String name) {
        assert name.codePointCount(0, name.length()) > 0;
        final int levels = this.levels;
        Path path = root;
        int idx = 0;
        for (int level = 0; level < levels; level ++) {
            int newIdx = name.offsetByCodePoints(idx, 1);
            path = path.resolve(name.substring(idx, newIdx));
            idx = newIdx;
            if (idx == name.length()) {
                break;
            }
        }
        return path.resolve(name + ".xml");
    }

    public ModifiableRealmIdentity createRealmIdentity(final String name) {
        if (name.isEmpty()) {
            throw ElytronMessages.log.invalidEmptyName();
        }
        final String finalName = nameRewriter.rewriteName(name);
        if (finalName == null) {
            throw ElytronMessages.log.invalidName();
        }
        return new Identity(finalName, pathFor(finalName));
    }

    public Iterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
        return subIterator(root, levels);
    }

    private Iterator<ModifiableRealmIdentity> subIterator(final Path root, final int levels) {
        if (levels == 0) {
            final Iterator<Path> iterator;
            try {
                iterator = Files.newDirectoryStream(root, "*.xml").iterator();
            } catch (IOException e) {
                return Collections.emptyIterator();
            }
            return new Iterator<ModifiableRealmIdentity>() {

                public boolean hasNext() {
                    return iterator.hasNext();
                }

                public ModifiableRealmIdentity next() {
                    final Path path = iterator.next();
                    final String fileName = path.getFileName().toString();
                    return createRealmIdentity(fileName.substring(0, fileName.length() - 4));
                }
            };
        } else {
            final Iterator<Path> iterator;
            try {
                iterator = Files.newDirectoryStream(root, entry -> {
                    final String fileName = entry.getFileName().toString();
                    return fileName.length() == 1 && !fileName.equals(".") && Files.isDirectory(entry);
                }).iterator();
            } catch (IOException e) {
                return Collections.emptyIterator();
            }
            return new Iterator<ModifiableRealmIdentity>() {
                private Iterator<ModifiableRealmIdentity> subIterator;

                public boolean hasNext() {
                    for (;;) {
                        if (subIterator == null) {
                            if (! iterator.hasNext()) {
                                return false;
                            }
                            final Path path = iterator.next();
                            subIterator = subIterator(path, levels - 1);
                        } else if (subIterator.hasNext()) {
                            return true;
                        } else {
                            subIterator = null;
                        }
                    }
                }

                public ModifiableRealmIdentity next() {
                    if (! hasNext()) {
                        throw new NoSuchElementException();
                    }
                    return subIterator.next();
                }
            };
        }
    }

    public SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    @FunctionalInterface
    interface CredentialParseFunction {
        void parseCredential(String name, String algorithm, String format, String body) throws RealmUnavailableException, XMLStreamException;
    }

    class Identity implements ModifiableRealmIdentity {

        private static final String BASE64_FORMAT = "base64";
        private static final String MCF_FORMAT = "crypt";

        private final String name;
        private final Path path;

        Identity(final String name, final Path path) {
            this.name = name;
            this.path = path;
        }

        public SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            Map<String, Credential> credentials = loadCredentials();
            return credentials.containsKey(credentialName) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
        }

        public Credential getCredential(final String credentialName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            Map<String, Credential> credentials = loadCredentials();
            return credentials.get(credentialName);
        }

        public boolean verifyEvidence(final String credentialName, final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            Assert.checkNotNullParam("credential", evidence);
            // we only know how to verify plain-text passwords
            ClearPassword clearPassword = null;
            if (evidence instanceof PasswordGuessEvidence) {
                try {
                    ClearPasswordSpec keySpec = new ClearPasswordSpec(((PasswordGuessEvidence) evidence).getGuess());
                    PasswordFactory instance = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
                    clearPassword = (ClearPassword) instance.generatePassword(keySpec);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw ElytronMessages.log.invalidCredentialTypeSpecified();
                }
            } else  if (evidence instanceof ClearPassword) {
                clearPassword = (ClearPassword) evidence;
            }
            if (clearPassword != null) {
                Map<String, Credential> credentials = loadCredentials();
                Credential storedCredential = credentials.get(credentialName);
                if (storedCredential instanceof PasswordCredential) try {
                    final Password storedPassword = ((PasswordCredential) storedCredential).getPassword();
                    final PasswordFactory passwordFactory = PasswordFactory.getInstance(storedPassword.getAlgorithm());
                    return passwordFactory.verify(storedPassword, clearPassword.getPassword());
                } catch (NoSuchAlgorithmException | InvalidKeyException ignored) {
                    // ignore
                }
            }
            return false;
        }

        private Map<String, Credential> loadCredentials() throws RealmUnavailableException {
            final LoadedIdentity loadedIdentity = loadIdentity(false, true);
            return loadedIdentity == null ? Collections.emptyMap() : loadedIdentity.getCredentials();
        }

        public boolean exists() throws RealmUnavailableException {
            return Files.exists(path);
        }

        public void delete() throws RealmUnavailableException {
            try {
                Files.delete(path);
            } catch (NoSuchFileException e) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            } catch (IOException e) {
                throw ElytronMessages.log.fileSystemRealmDeleteFailed(name, e);
            }
        }

        private String tempSuffix() {
            final ThreadLocalRandom random = ThreadLocalRandom.current();
            char[] array = new char[12];
            for (int i = 0; i < array.length; i ++) {
                int idx = random.nextInt(36);
                if (idx < 26) {
                    array[i] = (char) ('A' + idx);
                } else {
                    array[i] = (char) ('0' + idx - 26);
                }
            }
            return new String(array);
        }

        private Path tempPath() {
            Path parent = path.getParent();
            File file = parent.toFile();
            if (!file.exists()) {
                file.mkdirs();
            }
            return parent.resolve(path.getFileName().toString() + '.' + tempSuffix());
        }

        public void create() throws RealmUnavailableException {
            for (;;) {
                final Path tempPath = tempPath();
                final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
                try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(tempPath, WRITE, CREATE_NEW, DSYNC))) {
                    try (AutoCloseableXMLStreamWriterHolder holder = new AutoCloseableXMLStreamWriterHolder(xmlOutputFactory.createXMLStreamWriter(outputStream))) {
                        final XMLStreamWriter streamWriter = holder.getXmlStreamWriter();
                        // create empty identity
                        streamWriter.writeStartDocument();
                        streamWriter.writeCharacters("\n");
                        streamWriter.writeStartElement("identity");
                        streamWriter.writeDefaultNamespace(ELYTRON_1_0);
                        streamWriter.writeEndElement();
                        streamWriter.writeEndDocument();
                    } catch (XMLStreamException e) {
                        throw ElytronMessages.log.fileSystemRealmFailedToWrite(tempPath, name, e);
                    }
                } catch (FileAlreadyExistsException ignored) {
                    // try a new name
                    continue;
                } catch (IOException e) {
                    throw ElytronMessages.log.fileSystemRealmFailedToOpen(tempPath, name, e);
                }
                try {
                    Files.createLink(path, tempPath);
                } catch (FileAlreadyExistsException e) {
                    try {
                        Files.delete(tempPath);
                    } catch (IOException e2) {
                        e.addSuppressed(e2);
                    }
                    throw ElytronMessages.log.fileSystemRealmAlreadyExists(name, e);
                } catch (IOException e) {
                    throw ElytronMessages.log.fileSystemRealmFailedToWrite(tempPath, name, e);
                }
                try {
                    Files.delete(tempPath);
                } catch (IOException ignored) {
                    // nothing we can do
                }
                return;
            }
        }

        public void deleteCredential(final String credentialName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            final LoadedIdentity loadedIdentity = loadIdentity(false, false);
            if (loadedIdentity == null) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            }

            Map<String, Credential> credentials = loadedIdentity.getCredentials();
            credentials.remove(credentialName);

            final LoadedIdentity newIdentity = new LoadedIdentity(name, credentials, loadedIdentity.getAttributes());
            replaceIdentity(newIdentity);
        }

        public void setCredential(final String credentialName, final Credential credential) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            Assert.checkNotNullParam("credential", credential);
            final LoadedIdentity loadedIdentity = loadIdentity(false, false);
            if (loadedIdentity == null) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            }

            Map<String, Credential> credentials = loadedIdentity.getCredentials();
            if ( ! (credentials instanceof HashMap)) credentials = new HashMap<>(credentials);
            credentials.put(credentialName, credential);

            final LoadedIdentity newIdentity = new LoadedIdentity(name, credentials, loadedIdentity.getAttributes());
            replaceIdentity(newIdentity);
        }

        public void setCredentials(final Map<String, Credential> credentials) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentials", credentials);
            final LoadedIdentity loadedIdentity = loadIdentity(true, false);
            if (loadedIdentity == null) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            }

            final LoadedIdentity newIdentity = new LoadedIdentity(name, credentials, loadedIdentity.getAttributes());
            replaceIdentity(newIdentity);
        }

        public void setAttributes(final Attributes attributes) throws RealmUnavailableException {
            Assert.checkNotNullParam("attributes", attributes);
            final LoadedIdentity loadedIdentity = loadIdentity(false, true);
            if (loadedIdentity == null) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            }
            final LoadedIdentity newIdentity = new LoadedIdentity(name, loadedIdentity.getCredentials(), attributes);
            replaceIdentity(newIdentity);
        }

        private void replaceIdentity(final LoadedIdentity newIdentity) throws RealmUnavailableException {
            for (;;) {
                final Path tempPath = tempPath();
                try {
                    final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
                    try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(tempPath, WRITE, CREATE_NEW, DSYNC))) {
                        try (AutoCloseableXMLStreamWriterHolder holder = new AutoCloseableXMLStreamWriterHolder(xmlOutputFactory.createXMLStreamWriter(outputStream))) {
                            writeIdentity(holder.getXmlStreamWriter(), newIdentity);
                        } catch (XMLStreamException | InvalidKeySpecException | NoSuchAlgorithmException | CertificateEncodingException e) {
                            throw ElytronMessages.log.fileSystemRealmFailedToWrite(tempPath, name, e);
                        }
                    } catch (FileAlreadyExistsException ignored) {
                        // try a new name
                        continue;
                    } catch (IOException e) {
                        try {
                            Files.deleteIfExists(tempPath);
                        } catch (IOException e2) {
                            e.addSuppressed(e2);
                        }
                        throw ElytronMessages.log.fileSystemRealmFailedToOpen(tempPath, name, e);
                    }
                    try {
                        Files.delete(path);
                    } catch (IOException e) {
                        throw ElytronMessages.log.fileSystemUpdatedFailed(path.toAbsolutePath().toString(), e);
                    }
                    try {
                        Files.createLink(path, tempPath);
                    } catch (FileAlreadyExistsException e) {
                        try {
                            Files.deleteIfExists(tempPath);
                        } catch (IOException e2) {
                            e.addSuppressed(e2);
                        }
                        throw ElytronMessages.log.fileSystemRealmAlreadyExists(name, e);
                    } catch (IOException e) {
                        throw ElytronMessages.log.fileSystemRealmFailedToWrite(tempPath, name, e);
                    }
                    try {
                        Files.delete(tempPath);
                    } catch (IOException ignored) {
                        // nothing we can do
                    }
                    return;
                } catch (Throwable t) {
                    try {
                        Files.delete(tempPath);
                    } catch (IOException e) {
                        t.addSuppressed(e);
                    }
                    throw t;
                }
            }
        }

        private void writeIdentity(final XMLStreamWriter streamWriter, final LoadedIdentity newIdentity) throws XMLStreamException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateEncodingException {
            streamWriter.writeStartDocument();
            streamWriter.writeCharacters("\n");
            streamWriter.writeStartElement("identity");
            streamWriter.writeDefaultNamespace(ELYTRON_1_0);

            if (newIdentity.getCredentials().size() > 0) {
                streamWriter.writeCharacters("\n    ");
                streamWriter.writeStartElement("credentials");
                for (Map.Entry<String, Credential> entry : newIdentity.getCredentials().entrySet()) {
                    streamWriter.writeCharacters("\n        ");
                    final Credential credential = entry.getValue();
                    if (credential instanceof PasswordCredential) {
                        Password password = ((PasswordCredential) credential).getPassword();
                        if (password instanceof OneTimePassword) {
                            final OneTimePassword otp = (OneTimePassword) password;
                            otp.getHash();
                            streamWriter.writeStartElement("otp");
                            streamWriter.writeAttribute("name", entry.getKey());
                            streamWriter.writeAttribute("algorithm", otp.getAlgorithm());
                            streamWriter.writeAttribute("hash", ByteIterator.ofBytes(otp.getHash()).base64Encode().drainToString());
                            streamWriter.writeAttribute("seed", ByteIterator.ofBytes(otp.getSeed()).base64Encode().drainToString());
                            streamWriter.writeAttribute("sequence", Integer.toString(otp.getSequenceNumber()));
                            streamWriter.writeEndElement();
                        } else if (password instanceof Password) {
                            streamWriter.writeStartElement("password");
                            String format;
                            String algorithm = password.getAlgorithm();
                            String passwordString;
                            byte[] encoded = BasicPasswordSpecEncoding.encode(password);

                            if (encoded != null) {
                                format = BASE64_FORMAT;
                                passwordString = ByteIterator.ofBytes(encoded).base64Encode().drainToString();
                            } else {
                                format = MCF_FORMAT;
                                passwordString = ModularCrypt.encodeAsString(password);
                            }

                            streamWriter.writeAttribute("name", entry.getKey());
                            streamWriter.writeAttribute("algorithm", algorithm);
                            streamWriter.writeAttribute("format", format);
                            streamWriter.writeCharacters(passwordString.toString());
                            streamWriter.writeEndElement();
                        }
                    }
                }
                streamWriter.writeCharacters("\n    ");
                streamWriter.writeEndElement();
            }
            final Iterator<Attributes.Entry> entryIter = newIdentity.getAttributes().entries().iterator();
            if (entryIter.hasNext()) {
                streamWriter.writeCharacters("\n    ");
                streamWriter.writeStartElement("attributes");
                do {
                    final Attributes.Entry entry = entryIter.next();
                    for (String value : entry) {
                        streamWriter.writeCharacters("\n        ");
                        streamWriter.writeStartElement("attribute");
                        streamWriter.writeAttribute("name", entry.getKey());
                        streamWriter.writeAttribute("value", value);
                        streamWriter.writeEndElement();
                    }
                } while (entryIter.hasNext());
                streamWriter.writeCharacters("\n    ");
                streamWriter.writeEndElement();
            }
            streamWriter.writeEndElement();
            streamWriter.writeEndDocument();
        }

        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            final LoadedIdentity loadedIdentity = loadIdentity(true, false);
            return loadedIdentity == null ? AuthorizationIdentity.EMPTY : AuthorizationIdentity.basicIdentity(loadedIdentity.getAttributes());
        }

        private LoadedIdentity loadIdentity(final boolean skipCredentials, final boolean skipAttributes) throws RealmUnavailableException {
            try (InputStream inputStream = Files.newInputStream(path, READ)) {
                final XMLInputFactory inputFactory = XMLInputFactory.newFactory();
                inputFactory.setProperty(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
                inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
                inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
                inputFactory.setProperty(XMLInputFactory.IS_COALESCING, Boolean.TRUE);
                try (final AutoCloseableXMLStreamReaderHolder holder = new AutoCloseableXMLStreamReaderHolder(inputFactory.createXMLStreamReader(inputStream, "UTF-8"))) {
                    final XMLStreamReader streamReader = holder.getXmlStreamReader();
                    return parseIdentity(streamReader, skipCredentials, skipAttributes);
                } catch (XMLStreamException e) {
                    throw ElytronMessages.log.fileSystemRealmFailedToRead(path, name, e);
                }
            } catch (NoSuchFileException | FileNotFoundException ignored) {
                return null;
            } catch (IOException e) {
                throw ElytronMessages.log.fileSystemRealmFailedToOpen(path, name, e);
            }
        }

        private LoadedIdentity parseIdentity(final XMLStreamReader streamReader, final boolean skipCredentials, final boolean skipRoles) throws RealmUnavailableException, XMLStreamException {
            final int tag = streamReader.nextTag();
            if (tag != START_ELEMENT || ! ELYTRON_1_0.equals(streamReader.getNamespaceURI()) || ! "identity".equals(streamReader.getLocalName())) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }
            return parseIdentityContents(streamReader, skipCredentials, skipRoles);
        }

        private LoadedIdentity parseIdentityContents(final XMLStreamReader streamReader, final boolean skipCredentials, final boolean skipRoles) throws RealmUnavailableException, XMLStreamException {
            final int attributeCount = streamReader.getAttributeCount();
            if (attributeCount > 0) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }
            Map<String, Credential> credentials = Collections.emptyMap();
            Attributes attributes = Attributes.EMPTY;
            boolean gotCredentials = false;
            boolean gotRoles = false;
            for (;;) {
                if (streamReader.isEndElement()) {
                    return new LoadedIdentity(name, credentials, attributes);
                }
                if (! ELYTRON_1_0.equals(streamReader.getNamespaceURI())) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
                if (! gotCredentials && "credentials".equals(streamReader.getLocalName())) {
                    gotCredentials = true;
                    if (skipCredentials) {
                        consumeContent(streamReader);
                    } else {
                        credentials = parseCredentials(streamReader);
                    }
                } else if (! gotRoles && "attributes".equals(streamReader.getLocalName())) {
                    gotRoles = true;
                    if (skipRoles) {
                        consumeContent(streamReader);
                    } else {
                        attributes = parseAttributes(streamReader);
                    }
                }
                streamReader.nextTag();
            }
        }

        private Map<String, Credential> parseCredentials(final XMLStreamReader streamReader) throws RealmUnavailableException, XMLStreamException {
            final int attributeCount = streamReader.getAttributeCount();
            if (attributeCount > 0) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }
            if (streamReader.nextTag() == END_ELEMENT) {
                return Collections.emptyMap();
            }
            Map<String, Credential> credentials = new HashMap<>();
            do {
                if (! ELYTRON_1_0.equals(streamReader.getNamespaceURI())) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
                if ("password".equals(streamReader.getLocalName())) {
                    parsePassword(credentials, streamReader);
                } else if ("private-key".equals(streamReader.getLocalName())) {
                    parsePrivateKey(credentials, streamReader);
                } else if ("certificate".equals(streamReader.getLocalName())) {
                    parseCertificate(credentials, streamReader);
                } else if ("otp".equals(streamReader.getLocalName())) {
                    parseOtp(credentials, streamReader);
                } else {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
            } while (streamReader.nextTag() != END_ELEMENT);
            return credentials;
        }

        private void parseCredential(final XMLStreamReader streamReader, CredentialParseFunction function) throws RealmUnavailableException, XMLStreamException {
            final int attributeCount = streamReader.getAttributeCount();
            String name = null;
            String algorithm = null;
            String format = null;
            for (int i = 0; i < attributeCount; i ++) {
                String namespace = streamReader.getAttributeNamespace(i);
                if (namespace != null && !namespace.equals("")) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
                final String localName = streamReader.getAttributeLocalName(i);
                if ("name".equals(localName)) {
                    name = streamReader.getAttributeValue(i);
                } else if ("algorithm".equals(localName)) {
                    algorithm = streamReader.getAttributeValue(i);
                } else if ("format".equals(localName)) {
                    format = streamReader.getAttributeValue(i);
                } else {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
            }
            final String text = streamReader.getElementText().trim();
            function.parseCredential(name, algorithm, format, text);
        }

        private void parseCertificate(final Map<String, Credential> credentials, final XMLStreamReader streamReader) throws RealmUnavailableException, XMLStreamException {
            parseCredential(streamReader, (name, algorithm, format, text) -> {
                if (algorithm == null) algorithm = "X.509";
                if (format == null) format = "X.509";
                try {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance(algorithm);
                    credentials.put(name, new X509CertificateChainPublicCredential((X509Certificate) certificateFactory.generateCertificate(
                            CodePointIterator.ofString(text).base64Decode().asInputStream())));
                } catch (CertificateException | ClassCastException e) {
                    throw ElytronMessages.log.fileSystemRealmCertificateReadError(format, path, streamReader.getLocation().getLineNumber(), name);
                }
            });
        }

        private void parsePrivateKey(final Map<String, Credential> credentials, final XMLStreamReader streamReader) throws RealmUnavailableException, XMLStreamException {
            parseCredential(streamReader, (name, algorithm, format, text) -> {
                if (algorithm == null) {
                    throw ElytronMessages.log.fileSystemRealmMissingAttribute("algorithm", path, streamReader.getLocation().getLineNumber(), name);
                }
                // do nothing for now
            });
        }

        private void parsePassword(final Map<String, Credential> credentials, final XMLStreamReader streamReader) throws XMLStreamException, RealmUnavailableException {
            parseCredential(streamReader, (name, algorithm, format, text) -> {
                try {
                    if (BASE64_FORMAT.equals(format)) {
                        byte[] passwordBytes = CodePointIterator.ofChars(text.toCharArray()).base64Decode().drain();
                        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
                        PasswordSpec passwordSpec = BasicPasswordSpecEncoding.decode(passwordBytes);

                        if (passwordSpec != null) {
                            credentials.put(name, new PasswordCredential(passwordFactory.generatePassword(passwordSpec)));
                        } else {
                            throw ElytronMessages.log.fileSystemRealmInvalidPasswordAlgorithm(algorithm, path, streamReader.getLocation().getLineNumber(), name);
                        }
                    } else if (MCF_FORMAT.equals(format)) {
                        credentials.put(name, new PasswordCredential(ModularCrypt.decode(text)));
                    } else {
                        throw ElytronMessages.log.fileSystemRealmInvalidPasswordFormat(format, path, streamReader.getLocation().getLineNumber(), name);
                    }
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
            });
        }

        private void parseOtp(final Map<String, Credential> credentials, final XMLStreamReader streamReader) throws XMLStreamException, RealmUnavailableException {
            String name = null;
            String algorithm = null;
            byte[] hash = null;
            byte[] seed = null;
            int sequenceNumber = 0;

            final int attributeCount = streamReader.getAttributeCount();
            for (int i = 0; i < attributeCount; i ++) {
                String namespace = streamReader.getAttributeNamespace(i);
                if (namespace != null && !namespace.equals("")) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
                final String localName = streamReader.getAttributeLocalName(i);
                if ("name".equals(localName)) {
                    name = streamReader.getAttributeValue(i);
                } else if ("algorithm".equals(localName)) {
                    algorithm = streamReader.getAttributeValue(i);
                } else if ("hash".equals(localName)) {
                    hash = CodePointIterator.ofString(streamReader.getAttributeValue(i)).base64Decode().drain();
                } else if ("seed".equals(localName)) {
                    seed = CodePointIterator.ofString(streamReader.getAttributeValue(i)).base64Decode().drain();
                } else if ("sequence".equals(localName)) {
                    sequenceNumber = Integer.parseInt(streamReader.getAttributeValue(i));
                } else {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
            }

            if (streamReader.nextTag() != END_ELEMENT) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }

            try {
                PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm);
                Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(hash, seed, sequenceNumber));
                credentials.put(name, new PasswordCredential(password));
            } catch (InvalidKeySpecException e) {
                throw ElytronMessages.log.fileSystemRealmInvalidOtpDefinition(path, streamReader.getLocation().getLineNumber(), name, e);
            } catch (NoSuchAlgorithmException e) {
                throw ElytronMessages.log.fileSystemRealmInvalidOtpAlgorithm(algorithm, path, streamReader.getLocation().getLineNumber(), name, e);
            }
        }

        private Attributes parseAttributes(final XMLStreamReader streamReader) throws RealmUnavailableException, XMLStreamException {
            final int attributeCount = streamReader.getAttributeCount();
            if (attributeCount > 0) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }
            int tag = streamReader.nextTag();
            if (tag == END_ELEMENT) {
                return Attributes.EMPTY;
            }
            Attributes attributes = new MapAttributes();
            do {
                if (! ELYTRON_1_0.equals(streamReader.getNamespaceURI())) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
                if ("attribute".equals(streamReader.getLocalName())) {
                    parseAttribute(streamReader, attributes);
                } else {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
            } while (streamReader.nextTag() == START_ELEMENT);
            return attributes;
        }

        private void parseAttribute(final XMLStreamReader streamReader, final Attributes attributes) throws XMLStreamException, RealmUnavailableException {
            String name = null;
            String value = null;
            final int attributeCount = streamReader.getAttributeCount();
            for (int i = 0; i < attributeCount; i++) {
                String namespace = streamReader.getAttributeNamespace(i);
                if (namespace != null && !namespace.equals("")) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), this.name);
                }
                if ("name".equals(streamReader.getAttributeLocalName(i))) {
                    name = streamReader.getAttributeValue(i);
                } else if ("value".equals(streamReader.getAttributeLocalName(i))) {
                    value = streamReader.getAttributeValue(i);
                } else {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), this.name);
                }
            }
            if (name == null) {
                throw ElytronMessages.log.fileSystemRealmMissingAttribute("name", path, streamReader.getLocation().getLineNumber(), this.name);
            }
            if (value == null) {
                throw ElytronMessages.log.fileSystemRealmMissingAttribute("value", path, streamReader.getLocation().getLineNumber(), this.name);
            }
            attributes.addLast(name, value);
            if (streamReader.nextTag() != END_ELEMENT) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), this.name);
            }
        }

        private void consumeContent(final XMLStreamReader reader) throws XMLStreamException {
            while (reader.hasNext()) {
                switch (reader.next()) {
                    case START_ELEMENT: {
                        consumeContent(reader);
                        break;
                    }
                    case END_ELEMENT: {
                        return;
                    }
                }
            }
        }
    }

    final class LoadedIdentity {
        private final String name;
        private final Map<String, Credential> credentials;
        private final Attributes attributes;

        LoadedIdentity(final String name, final Map<String, Credential> credentials, final Attributes attributes) {
            this.name = name;
            this.credentials = credentials;
            this.attributes = attributes;
        }

        public String getName() {
            return name;
        }

        public Attributes getAttributes() {
            return attributes;
        }

        Map<String, Credential> getCredentials() {
            return credentials;
        }
    }

    static class AutoCloseableXMLStreamReaderHolder implements AutoCloseable {
        private final XMLStreamReader xmlStreamReader;

        AutoCloseableXMLStreamReaderHolder(final XMLStreamReader xmlStreamReader) {
            this.xmlStreamReader = xmlStreamReader;
        }

        public void close() throws XMLStreamException {
            xmlStreamReader.close();
        }

        public XMLStreamReader getXmlStreamReader() {
            return xmlStreamReader;
        }
    }

    static class AutoCloseableXMLStreamWriterHolder implements AutoCloseable {
        private final XMLStreamWriter xmlStreamWriter;

        AutoCloseableXMLStreamWriterHolder(final XMLStreamWriter xmlStreamWriter) {
            this.xmlStreamWriter = xmlStreamWriter;
        }

        public void close() throws XMLStreamException {
            xmlStreamWriter.close();
        }

        public XMLStreamWriter getXmlStreamWriter() {
            return xmlStreamWriter;
        }
    }
}
