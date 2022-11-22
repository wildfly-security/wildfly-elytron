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

package org.wildfly.security.auth.realm;

import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.DSYNC;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static javax.xml.stream.XMLStreamConstants.END_ELEMENT;
import static javax.xml.stream.XMLStreamConstants.START_ELEMENT;
import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.crypto.SecretKey;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wildfly.common.Assert;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.codec.Base32Alphabet;
import org.wildfly.common.codec.Base64Alphabet;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.IdentitySharedExclusiveLock.IdentityLock;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableRealmIdentityIterator;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.encryption.CipherUtil;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.BasicPasswordSpecEncoding;
import org.wildfly.security.password.spec.Encoding;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.util.ModularCrypt;
import org.wildfly.security.permission.ElytronPermission;
import org.xml.sax.SAXException;

/**
 * A simple filesystem-backed security realm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class FileSystemSecurityRealm implements ModifiableSecurityRealm, CacheableSecurityRealm {

    static final ElytronPermission CREATE_SECURITY_REALM = ElytronPermission.forName("createSecurityRealm");

    private final Supplier<Provider[]> providers;
    static final Map<String, Version> KNOWN_NAMESPACES;

    private enum Version {

        VERSION_1_0("urn:elytron:1.0", null),
        VERSION_1_0_1("urn:elytron:1.0.1", VERSION_1_0),
        VERSION_1_1("urn:elytron:identity:1.1", VERSION_1_0_1),
        VERSION_1_2("urn:elytron:identity:1.2", VERSION_1_1);

        final String namespace;

        /*
         * In the future we could support multiple parents but wait until that becomes a reality before adding it.
         */
        final Version parent;

        Version(String namespace, Version parent) {
            this.namespace = namespace;
            this.parent = parent;
        }

        String getNamespace() {
            return namespace;
        }

        boolean isAtLeast(Version version) {
            return this.equals(version) || (parent != null ? parent.isAtLeast(version) : false);
        }

    }

    static {
        Map<String, Version> knownNamespaces = new HashMap<>();
        for (Version version : Version.values()) {
            knownNamespaces.put(version.namespace, version);
        }
        KNOWN_NAMESPACES = Collections.unmodifiableMap(knownNamespaces);
    }

    private final Path root;
    private final NameRewriter nameRewriter;
    private final int levels;
    private final boolean encoded;
    private final Charset hashCharset;
    private final Encoding hashEncoding;
    private final SecretKey secretKey;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final ConcurrentHashMap<String, IdentitySharedExclusiveLock> realmIdentityLocks = new ConcurrentHashMap<>();

    /**
     * Construct a new instance of the FileSystemSecurityRealmBuilder.
     *
     * @return the new FileSystemSecurityRealmBuilder instance
     */
    public static FileSystemSecurityRealmBuilder builder() {
        return new FileSystemSecurityRealmBuilder();
    }
    /**
     * Construct a new instance.
     *
     * Construction with enabled security manager requires {@code createSecurityRealm} {@link ElytronPermission}.
     *
     * @param root the root path of the identity store
     * @param nameRewriter the name rewriter to apply to looked up names
     * @param levels the number of levels of directory hashing to apply
     * @param encoded whether identity names should be BASE32 encoded before using as filename (only applies if the security realm is unencrypted)
     * @param hashCharset the character set to use when converting password strings to a byte array. Uses UTF-8 by default.
     * @param hashEncoding the string format for the hashed passwords. Uses Base64 by default.
     * @param providers The providers supplier
     * @param secretKey the SecretKey used to encrypt and decrypt the security realm (if {@code null}, the security realm will be unencrypted)
     * @param privateKey the PrivateKey used to verify the integrity of the security realm (if {@code null}, the security realm will not verify integrity)
     * @param publicKey the PublicKey used to verify the integrity of the security realm (if {@code null}, the security realm will not verify integrity)
     *
     */
    public FileSystemSecurityRealm(final Path root, final NameRewriter nameRewriter, final int levels, final boolean encoded, final Encoding hashEncoding, final Charset hashCharset, final Supplier<Provider[]> providers, final SecretKey secretKey, final PrivateKey privateKey, final PublicKey publicKey) {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_SECURITY_REALM);
        }
        this.root = root;
        this.nameRewriter = nameRewriter;
        this.levels = levels;
        this.encoded = secretKey == null && encoded;
        this.hashCharset = hashCharset != null ? hashCharset : StandardCharsets.UTF_8;
        this.hashEncoding = hashEncoding != null ? hashEncoding : Encoding.BASE64;
        this.providers = providers != null ? providers : INSTALLED_PROVIDERS;
        this.secretKey = secretKey;
        this.privateKey = privateKey;
        this.publicKey = publicKey;

    }

    /**
     * Construct a new instance.
     *
     * Construction with enabled security manager requires {@code createSecurityRealm} {@link ElytronPermission}.
     *
     * @param root the root path of the identity store
     * @param nameRewriter the name rewriter to apply to looked up names
     * @param levels the number of levels of directory hashing to apply
     * @param encoded whether identity names should be BASE32 encoded before using as filename
     * @param hashCharset the character set to use when converting password strings to a byte array. Uses UTF-8 by default.
     * @param hashEncoding the string format for the hashed passwords. Uses Base64 by default.
     * @param secretKey the SecretKey used to encrypt and decrypt the security realm (if {@code null}, the security realm will be unencrypted)
     */
    public FileSystemSecurityRealm(final Path root, final NameRewriter nameRewriter, final int levels, final boolean encoded, final Encoding hashEncoding, final Charset hashCharset, final SecretKey secretKey) {
        this(root, nameRewriter, levels, encoded, hashEncoding, hashCharset, INSTALLED_PROVIDERS, secretKey, null, null);
    }

    /**
     * Construct a new instance.
     *
     * Construction with enabled security manager requires {@code createSecurityRealm} {@link ElytronPermission}.
     *
     * @param root the root path of the identity store
     * @param nameRewriter the name rewriter to apply to looked up names
     * @param levels the number of levels of directory hashing to apply
     * @param encoded whether identity names should be BASE32 encoded before using as filename
     * @param hashCharset the character set to use when converting password strings to a byte array. Uses UTF-8 by default.
     * @param hashEncoding the string format for the hashed passwords. Uses Base64 by default.
     */
    public FileSystemSecurityRealm(final Path root, final NameRewriter nameRewriter, final int levels, final boolean encoded, final Encoding hashEncoding, final Charset hashCharset) {
        this(root, nameRewriter, levels, encoded, hashEncoding, hashCharset, INSTALLED_PROVIDERS, null, null, null);
    }

    /**
     * Construct a new instance.
     *
     * Construction with enabled security manager requires {@code createSecurityRealm} {@link ElytronPermission}.
     *
     * @param root the root path of the identity store
     * @param nameRewriter the name rewriter to apply to looked up names
     * @param levels the number of levels of directory hashing to apply
     * @param encoded whether identity names should by BASE32 encoded before using as filename
     */
    public FileSystemSecurityRealm(final Path root, final NameRewriter nameRewriter, final int levels, final boolean encoded) {
        this(root, nameRewriter, levels, encoded, Encoding.BASE64, StandardCharsets.UTF_8, INSTALLED_PROVIDERS, null, null, null);
    }

    /**
     * Construct a new instance.
     *
     * @param root the root path of the identity store
     * @param nameRewriter the name rewriter to apply to looked up names
     * @param levels the number of levels of directory hashing to apply
     */
    public FileSystemSecurityRealm(final Path root, final NameRewriter nameRewriter, final int levels) {
        this(root, nameRewriter, levels, true);
    }

    /**
     * Construct a new instance.
     *
     * @param root the root path of the identity store
     * @param nameRewriter the name rewriter to apply to looked up names
     * @param levels the number of levels of directory hashing to apply
     * @param hashEncoding the string format for hashed passwords. Uses Base64 by default.
     * @param hashCharset the character set to use when converting password strings to a byte array. Uses UTF-8 by default and must not be {@code null}.
     */
    public FileSystemSecurityRealm(final Path root, final NameRewriter nameRewriter, final int levels, final Encoding hashEncoding, final Charset hashCharset) {
        this(root, nameRewriter, levels, true, hashEncoding, hashCharset, INSTALLED_PROVIDERS, null, null, null);
    }



    /**
     * Construct a new instance.
     *
     * @param root the root path of the identity store
     * @param levels the number of levels of directory hashing to apply
     */
    public FileSystemSecurityRealm(final Path root, final int levels) {
        this(root, NameRewriter.IDENTITY_REWRITER, levels, true);
    }


    /**
     * Construct a new instance.
     *
     * @param root the root path of the identity store
     * @param levels the number of levels of directory hashing to apply
     * @param hashEncoding the string format for hashed passwords. Uses Base64 by default.
     * @param hashCharset the character set to use when converting password strings to a byte array. Uses UTF-8 by default and must not be {@code null}.
     */
    public FileSystemSecurityRealm(final Path root, final int levels, final Encoding hashEncoding, final Charset hashCharset) {
        this(root, NameRewriter.IDENTITY_REWRITER, levels, true, hashEncoding, hashCharset, INSTALLED_PROVIDERS, null, null, null);
    }

    /**
     * Construct a new instance with 2 levels of hashing.
     *
     * @param root the root path of the identity store
     */
    public FileSystemSecurityRealm(final Path root) {
        this(root, NameRewriter.IDENTITY_REWRITER, 2, true);
    }

    /**
     * Construct a new instance with 2 levels of hashing.
     *
     * @param root the root path of the identity store
     * @param hashEncoding the string format for hashed passwords. Uses Base64 by default.
     * @param hashCharset the character set to use when converting password strings to a byte array. Uses UTF-8 by default and must not be {@code null}
     */
    public FileSystemSecurityRealm(final Path root, final Encoding hashEncoding, final Charset hashCharset) {
        this(root, NameRewriter.IDENTITY_REWRITER, 2, true, hashEncoding, hashCharset, INSTALLED_PROVIDERS, null, null, null);
    }

    public FileSystemSecurityRealm(Path root, int levels, Supplier<Provider[]> providers) {
        this(root, NameRewriter.IDENTITY_REWRITER, levels, true, Encoding.BASE64, StandardCharsets.UTF_8, providers, null, null, null);
    }

    /**
     * Checks if the FileSystemSecurityRealm has Integrity checking enabled
     * @return {@code true} if Integrity checking is enabled, and {@code false} otherwise
     */
    public boolean hasIntegrityEnabled() {
        return privateKey != null && publicKey != null;
    }
    private Path pathFor(String name) {
        assert name.codePointCount(0, name.length()) > 0;
        String normalizedName = name;

        if (encoded) {
            normalizedName = Normalizer.normalize(name, Normalizer.Form.NFKC)
                    .toLowerCase(Locale.ROOT)
                    .replaceAll("[^a-z0-9]", "_");
        }
        if (secretKey != null || encoded) {
            String base32 = ByteIterator.ofBytes(new ByteStringBuilder().append(name).toArray())
                    .base32Encode(Base32Alphabet.STANDARD, false).drainToString();
            normalizedName = secretKey != null ? base32 : normalizedName + "-" + base32;
        }

        Path path = root;
        int idx = 0;
        for (int level = 0; level < levels; level ++) {
            int newIdx = normalizedName.offsetByCodePoints(idx, 1);
            path = path.resolve(normalizedName.substring(idx, newIdx));
            idx = newIdx;
            if (idx == normalizedName.length()) {
                break;
            }
        }

        return path.resolve(normalizedName + ".xml");
    }

    public Charset getHashCharset() {
        return this.hashCharset;
    }

    private String nameFor(Path path) {
        String fileName = path.toString();
        fileName = fileName.substring(0, fileName.length() - 4); // remove ".xml"

        if (secretKey != null) {
            CodePointIterator it = CodePointIterator.ofString(fileName);
            fileName = it.base32Decode(Base32Alphabet.STANDARD, false)
                    .asUtf8String().drainToString();
        } else if (encoded) {
            CodePointIterator it = CodePointIterator.ofString(fileName);
            it.delimitedBy('-').skipAll();
            it.next(); // skip '-'
            fileName = it.base32Decode(Base32Alphabet.STANDARD, false)
                    .asUtf8String().drainToString();
        }
        return fileName;
    }

    public RealmIdentity getRealmIdentity(final Principal principal) {
        return principal instanceof NamePrincipal ? getRealmIdentity(principal.getName(), false) : RealmIdentity.NON_EXISTENT;
    }

    @Override
    public ModifiableRealmIdentity getRealmIdentityForUpdate(final Principal principal) {
        return principal instanceof NamePrincipal ? getRealmIdentity(principal.getName(), true) : ModifiableRealmIdentity.NON_EXISTENT;
    }

    @Override
    public void registerIdentityChangeListener(Consumer<Principal> listener) {
        // no need to register the listener given that changes to identities are done through the realm
    }

    private ModifiableRealmIdentity getRealmIdentity(final String name, final boolean exclusive) {
        final String finalName = nameRewriter.rewriteName(name);
        if (finalName == null) {
            throw ElytronMessages.log.invalidName();
        }

        // Acquire the appropriate lock for the realm identity
        IdentitySharedExclusiveLock realmIdentityLock = getRealmIdentityLockForName(finalName);
        IdentityLock lock;
        if (exclusive) {
            lock = realmIdentityLock.lockExclusive();
        } else {
            lock = realmIdentityLock.lockShared();
        }
        return new Identity(finalName, pathFor(finalName), lock, hashCharset, hashEncoding, providers, secretKey, privateKey, publicKey, hasIntegrityEnabled());
    }

    @Override
    public ModifiableRealmIdentityIterator getRealmIdentityIterator() throws RealmUnavailableException {
        return subIterator(root, levels);
    }

    private ModifiableRealmIdentityIterator subIterator(final Path root, final int levels) {
        final DirectoryStream<Path> stream;
        final Iterator<Path> iterator;
        if (levels == 0) {
            try {
                stream = Files.newDirectoryStream(root, "*.xml");
                iterator = stream.iterator();
            } catch (IOException e) {
                ElytronMessages.log.debug("Unable to open directory", e);
                return ModifiableRealmIdentityIterator.emptyIterator();
            }
            return new ModifiableRealmIdentityIterator() {

                public boolean hasNext() {
                    if ( ! iterator.hasNext()) {
                        try {
                            close();
                        } catch (IOException e) {
                            ElytronMessages.log.debug("Unable to close the stream", e);
                        }
                    }
                    return iterator.hasNext();
                }

                public ModifiableRealmIdentity next() {
                    final Path path = iterator.next();
                    final String name = nameFor(path.getFileName());
                    return getRealmIdentityForUpdate(new NamePrincipal(name));
                }

                public void close() throws RealmUnavailableException {
                    try {
                        stream.close();
                    } catch (IOException e) {
                        ElytronMessages.log.debug("Unable to close the stream", e);
                    }
                }
            };
        } else {
            try {
                stream = Files.newDirectoryStream(root, entry -> {
                    final String fileName = entry.getFileName().toString();
                    return fileName.length() == 1 && !fileName.equals(".") && Files.isDirectory(entry);
                });
                iterator = stream.iterator();
            } catch (IOException e) {
                ElytronMessages.log.debug("Unable to open directory", e);
                return ModifiableRealmIdentityIterator.emptyIterator();
            }
            return new ModifiableRealmIdentityIterator() {
                private ModifiableRealmIdentityIterator subIterator;

                public boolean hasNext() {
                    for (;;) {
                        if (subIterator == null) {
                            if (! iterator.hasNext()) {
                                try {
                                    close();
                                } catch (IOException e) {
                                    ElytronMessages.log.debug("Unable to close the stream", e);
                                }
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

                public void close() throws RealmUnavailableException {
                    try {
                        if (subIterator != null) subIterator.close();
                    } finally {
                        try {
                            stream.close();
                        } catch (IOException e) {
                            ElytronMessages.log.debug("Unable to close the stream", e);
                        }
                    }
                }
            };
        }
    }

    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    private IdentitySharedExclusiveLock getRealmIdentityLockForName(final String name) {
        IdentitySharedExclusiveLock realmIdentityLock = realmIdentityLocks.get(name);
        if (realmIdentityLock == null) {
            final IdentitySharedExclusiveLock newRealmIdentityLock = new IdentitySharedExclusiveLock();
            realmIdentityLock = realmIdentityLocks.putIfAbsent(name, newRealmIdentityLock);
            if (realmIdentityLock == null) {
                realmIdentityLock = newRealmIdentityLock;
            }
        }
        return realmIdentityLock;
    }

    @FunctionalInterface
    interface CredentialParseFunction {
        void parseCredential(String algorithm, String format, String body) throws RealmUnavailableException, XMLStreamException;
    }

    /**
     * Re-generate the signatures for all the identities in this realm.
     * This method is intended to be called after updating the key pair used by this realm.
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    public void updateRealmKeyPair() throws RealmUnavailableException {
        if (! hasIntegrityEnabled()) {
            throw ElytronMessages.log.integrityNotEnabled(root.toString());
        }
        ModifiableRealmIdentityIterator realmIterator = this.getRealmIdentityIterator();
        while (realmIterator.hasNext()) {
            Identity identity = (Identity) realmIterator.next();
            try {
                identity.writeDigitalSignature(identity.path, identity.name, false);
            } finally {
                identity.dispose();
            }
        }
        realmIterator.close();
    }

    /**
     * Verify the integrity of each identity file in this realm.
     * @return {@code true} if the integrity of all the identity files in the realm is successfully verified and {@code false} otherwise
     *
     */
    public IntegrityResult verifyRealmIntegrity() throws RealmUnavailableException {
        if (! hasIntegrityEnabled()) {
            throw ElytronMessages.log.integrityNotEnabled(root.toString());
        }
        ArrayList<String> failedIdentities = new ArrayList<>();
        ModifiableRealmIdentityIterator realmIterator = this.getRealmIdentityIterator();
        while (realmIterator.hasNext()) {
            Identity identity = (Identity) realmIterator.next();
            if(! identity.isIntegrityValid()) {
                failedIdentities.add(identity.name);
            }
            identity.dispose();
        }
        realmIterator.close();
        return new IntegrityResult(failedIdentities.isEmpty(), failedIdentities);
    }

    static class Identity implements ModifiableRealmIdentity {

        private static final String ENCRYPTION_FORMAT = "enc_base64";
        private static final String BASE64_FORMAT = "base64";
        private static final String MCF_FORMAT = "crypt";
        private static final String X509_FORMAT = "X.509";
        private static final String HEX = "hex";

        private final String name;
        private final Path path;
        private final Supplier<Provider[]> providers;
        private IdentityLock lock;
        private final Charset hashCharset;
        private final Encoding hashEncoding;
        private final SecretKey secretKey;
        private final PrivateKey privateKey;
        private final PublicKey publicKey;
        private final boolean integrityEnabled;

        Identity(final String name, final Path path, final IdentityLock lock, final Charset hashCharset, final Encoding hashEncoding, Supplier<Provider[]> providers, final SecretKey secretKey, final PrivateKey privateKey, final PublicKey publicKey, final boolean integrityEnabled) {
            this.name = name;
            this.path = path;
            this.lock = lock;
            this.hashCharset = hashCharset;
            this.hashEncoding = hashEncoding;
            this.providers = providers;
            this.secretKey = secretKey;
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.integrityEnabled = integrityEnabled;
        }

        public Principal getRealmIdentityPrincipal() {
            return new NamePrincipal(name);
        }

        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            List<Credential> credentials = loadCredentials();
            for (Credential credential : credentials) {
                if (credential.matches(credentialType, algorithmName, parameterSpec)) {
                    return SupportLevel.SUPPORTED;
                }
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return getCredential(credentialType, null);
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return getCredential(credentialType, algorithmName, null);
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            List<Credential> credentials = loadCredentials();
            for (Credential credential : credentials) {
                if (credential.matches(credentialType, algorithmName, parameterSpec)) {
                    return credentialType.cast(credential.clone());
                }
            }
            return null;
        }

        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            List<Credential> credentials = loadCredentials();
            for (Credential credential : credentials) {
                if (credential.canVerify(evidenceType, algorithmName)) {
                    ElytronMessages.log.tracef("FileSystemSecurityRealm - evidence verification SUPPORTED: type = [%s]  algorithm = [%s]  credentials = [%d]", evidenceType, algorithmName, credentials.size());
                    return SupportLevel.SUPPORTED;
                }
            }
            ElytronMessages.log.tracef("FileSystemSecurityRealm - evidence verification UNSUPPORTED: type = [%s]  algorithm = [%s]  credentials = [%d]", evidenceType, algorithmName, credentials.size());
            return SupportLevel.UNSUPPORTED;
        }

        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);

            if (ElytronMessages.log.isTraceEnabled()) {
                try {
                    final LoadedIdentity loadedIdentity = loadIdentity(false, true, false);
                    ElytronMessages.log.tracef("Trying to authenticate identity %s using FileSystemSecurityRealm", (loadedIdentity != null) ? loadedIdentity.getName() : "null");
                } catch (RealmUnavailableException e) {
                    if (e.getCause() instanceof IntegrityException) {
                        return false;
                    }
                    throw e;
                }
            }
            List<Credential> credentials = null;
            try {
                credentials = loadCredentials();
            } catch (RealmUnavailableException e) {
                if (e.getCause() instanceof IntegrityException) {
                    return false;
                }
                throw e;
            }
            ElytronMessages.log.tracef("FileSystemSecurityRealm - verification evidence [%s] against [%d] credentials...", evidence, credentials.size());
            for (Credential credential : credentials) {
                if (credential.canVerify(evidence)) {
                    boolean verified = false;
                    if (credential instanceof PasswordCredential) {
                        verified = ((PasswordCredential )credential).verify(providers, evidence, hashCharset);
                    } else {
                        verified = credential.verify(providers, evidence);
                    }
                    ElytronMessages.log.tracef("FileSystemSecurityRealm - verification against credential [%s] = %b", credential, verified);
                    return verified;
                }
            }
            ElytronMessages.log.tracef("FileSystemSecurityRealm - no credential able to verify evidence [%s]", evidence);
            return false;
        }

        List<Credential> loadCredentials() throws RealmUnavailableException {
            final LoadedIdentity loadedIdentity = loadIdentity(false, true, false);
            return loadedIdentity == null ? Collections.emptyList() : loadedIdentity.getCredentials();
        }

        public boolean exists() throws RealmUnavailableException {
            if (System.getSecurityManager() == null) {
                return Files.exists(path);
            }
            return AccessController.doPrivileged((PrivilegedAction<Boolean>) () -> Files.exists(path));
        }

        public void delete() throws RealmUnavailableException {
            if (System.getSecurityManager() == null) {
                deletePrivileged();
                return;
            }
            try {
                AccessController.doPrivileged((PrivilegedExceptionAction<Void>) this::deletePrivileged);
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof RealmUnavailableException) {
                    throw (RealmUnavailableException) e.getException();
                }
                throw new RuntimeException(e.getException());
            }
        }

        private Void deletePrivileged() throws RealmUnavailableException {
            try {
                Files.delete(path);
                return null;
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
            if (System.getSecurityManager() == null) {
                createPrivileged();
                return;
            }
            try {
                AccessController.doPrivileged((PrivilegedExceptionAction<Void>) this::createPrivileged);
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof RealmUnavailableException) {
                    throw (RealmUnavailableException) e.getException();
                }
                throw new RuntimeException(e.getException());
            }
        }

        private Void createPrivileged() throws RealmUnavailableException {
            for (;;) {
                final Path tempPath = tempPath();
                final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
                try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(tempPath, WRITE, CREATE_NEW, DSYNC))) {
                    try (AutoCloseableXMLStreamWriterHolder holder = new AutoCloseableXMLStreamWriterHolder(xmlOutputFactory.createXMLStreamWriter(outputStream))) {
                        String namespace = "";
                        if (integrityEnabled) {
                            namespace = Version.VERSION_1_2.getNamespace();
                        } else if (secretKey != null) {
                            namespace = Version.VERSION_1_1.getNamespace();
                        } else {
                            namespace = Version.VERSION_1_0.getNamespace();
                        }
                        final XMLStreamWriter streamWriter = holder.getXmlStreamWriter();
                        // create empty identity
                        streamWriter.writeStartDocument();
                        streamWriter.writeCharacters("\n");
                        streamWriter.writeStartElement("identity");
                        streamWriter.writeDefaultNamespace(namespace);
                        if (integrityEnabled) {
                            streamWriter.writeCharacters("\n    ");
                            streamWriter.writeStartElement("principal");
                            streamWriter.writeAttribute("name", secretKey != null ? CipherUtil.encrypt(name, secretKey) : name);
                            streamWriter.writeEndElement();
                            streamWriter.writeCharacters("\n    ");
                        }
                        streamWriter.writeEndElement();
                        streamWriter.writeEndDocument();
                    } catch (XMLStreamException | GeneralSecurityException e) {
                        throw ElytronMessages.log.fileSystemRealmFailedToWrite(tempPath, name, e);
                    }
                    if(integrityEnabled) {
                        try {
                            writeDigitalSignature(tempPath, this.name, false);
                        } catch (RealmUnavailableException e) {
                            throw ElytronMessages.log.unableToGenerateSignature(path.toString());
                        }
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
                return null;
            }
        }

        public void setCredentials(final Collection<? extends Credential> credentials) throws RealmUnavailableException {
            Assert.checkNotNullParam("credential", credentials);
            final LoadedIdentity loadedIdentity = loadIdentity(false, false, false);
            if (loadedIdentity == null) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            }

            final LoadedIdentity newIdentity = new LoadedIdentity(name, new ArrayList<>(credentials), loadedIdentity.getAttributes(),
                    hashEncoding, false);
            replaceIdentity(newIdentity);
        }

        public void setAttributes(final Attributes attributes) throws RealmUnavailableException {
            Assert.checkNotNullParam("attributes", attributes);
            final LoadedIdentity loadedIdentity = loadIdentity(false, true, false);
            if (loadedIdentity == null) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            }
            final LoadedIdentity newIdentity = new LoadedIdentity(name, loadedIdentity.getCredentials(), attributes, hashEncoding,
                    false);
            replaceIdentity(newIdentity);
        }

        @Override
        public Attributes getAttributes() throws RealmUnavailableException {
            final LoadedIdentity loadedIdentity = loadIdentity(true, false, false);
            if (loadedIdentity == null) {
                throw ElytronMessages.log.fileSystemRealmNotFound(name);
            }
            return loadedIdentity.getAttributes().asReadOnly();
        }

        private void replaceIdentity(final LoadedIdentity newIdentity) throws RealmUnavailableException {
            if (System.getSecurityManager() == null) {
                replaceIdentityPrivileged(newIdentity);
                return;
            }
            try {
                AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> replaceIdentityPrivileged(newIdentity));
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof RealmUnavailableException) {
                    throw (RealmUnavailableException) e.getException();
                }
                throw new RuntimeException(e.getException());
            }
        }

        /**
         * Replaces the given identity in place, modifying the namespace if necessary
         */
        private Void replaceIdentityPrivileged(final LoadedIdentity newIdentity) throws RealmUnavailableException {
            if (!isIntegrityValid() && !newIdentity.getUpgradeIdentity()) {
                throw new RealmUnavailableException(ElytronMessages.log.invalidIdentitySignature(name));
            }
            for (;;) {
                final Path tempPath = tempPath();
                try {
                    final XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newFactory();
                    try (OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(tempPath, WRITE, CREATE_NEW, DSYNC))) {
                        try (AutoCloseableXMLStreamWriterHolder holder = new AutoCloseableXMLStreamWriterHolder(xmlOutputFactory.createXMLStreamWriter(outputStream))) {
                            writeIdentity(holder.getXmlStreamWriter(), newIdentity);
                        } catch (XMLStreamException | InvalidKeySpecException | NoSuchAlgorithmException | CertificateEncodingException e) {
                            throw ElytronMessages.log.fileSystemRealmFailedToWrite(tempPath, name, e);
                        } catch (GeneralSecurityException e) {
                            throw ElytronMessages.log.fileSystemRealmEncryptionFailed(e);
                        }
                        if (integrityEnabled) {
                            try {
                                writeDigitalSignature(tempPath, name, newIdentity.getUpgradeIdentity());
                            } catch (RealmUnavailableException e) {
                                throw ElytronMessages.log.unableToGenerateSignature(path.toString());
                            }
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
                    return null;
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

        private Version requiredVersion(final LoadedIdentity identityToWrite) {
            // As new functionality is added we will identify if we need to use a later version
            // if new functionality is used then use the required schema version otherwise fallback
            // to an older version.

            if (integrityEnabled) {
                return Version.VERSION_1_2;
            } else if (secretKey != null) {
                return Version.VERSION_1_1;
            } else {
                return Version.VERSION_1_0;
            }
        }

        private void writeIdentity(final XMLStreamWriter streamWriter, final LoadedIdentity newIdentity) throws XMLStreamException, InvalidKeySpecException, NoSuchAlgorithmException, GeneralSecurityException {
            streamWriter.writeStartDocument();
            streamWriter.writeCharacters("\n");
            streamWriter.writeStartElement("identity");
            streamWriter.writeDefaultNamespace(requiredVersion(newIdentity).getNamespace());

            if (integrityEnabled) {
                streamWriter.writeCharacters("\n    ");
                streamWriter.writeStartElement("principal");
                streamWriter.writeAttribute("name", secretKey != null ? CipherUtil.encrypt(name, secretKey) : name);
                streamWriter.writeEndElement();
            }

            if (newIdentity.getCredentials().size() > 0) {
                streamWriter.writeCharacters("\n    ");
                streamWriter.writeStartElement("credentials");
                for (Credential credential : newIdentity.getCredentials()) {
                    streamWriter.writeCharacters("\n        ");
                    if (credential instanceof PasswordCredential) {
                        Password password = ((PasswordCredential) credential).getPassword();
                        if (password instanceof OneTimePassword) {
                            final OneTimePassword otp = (OneTimePassword) password;
                            streamWriter.writeStartElement("otp");
                            streamWriter.writeAttribute("algorithm", otp.getAlgorithm());
                            streamWriter.writeAttribute("hash", ByteIterator.ofBytes(otp.getHash()).base64Encode().drainToString());
                            streamWriter.writeAttribute("seed", ByteIterator.ofBytes(otp.getSeed().getBytes(StandardCharsets.US_ASCII)).base64Encode().drainToString());
                            streamWriter.writeAttribute("sequence", Integer.toString(otp.getSequenceNumber()));
                            streamWriter.writeEndElement();
                        } else {
                            streamWriter.writeStartElement("password");
                            String format;
                            String algorithm = password.getAlgorithm();
                            String passwordString;
                            byte[] encoded = BasicPasswordSpecEncoding.encode(password, providers);

                            if (secretKey != null) {
                                format = ENCRYPTION_FORMAT;
                                passwordString = ByteIterator.ofBytes(CipherUtil.encrypt(encoded, secretKey)).base64Encode().drainToString();
                            } else if (encoded != null) {
                                if (newIdentity.getHashEncoding() == Encoding.HEX) {
                                    format = HEX;
                                    passwordString = ByteIterator.ofBytes(encoded).hexEncode().drainToString();
                                } else {
                                    // default to base64
                                    format = BASE64_FORMAT;
                                    passwordString = ByteIterator.ofBytes(encoded).base64Encode().drainToString();
                                }
                            } else {
                                format = MCF_FORMAT;
                                passwordString = ModularCrypt.encodeAsString(password);
                            }

                            streamWriter.writeAttribute("algorithm", algorithm);
                            streamWriter.writeAttribute("format", format);
                            streamWriter.writeCharacters(passwordString);
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
                        streamWriter.writeAttribute("name", secretKey != null ? CipherUtil.encrypt(entry.getKey(), secretKey) : entry.getKey());
                        streamWriter.writeAttribute("value", secretKey != null ? CipherUtil.encrypt(value, secretKey) : value);
                        streamWriter.writeEndElement();
                    }
                } while (entryIter.hasNext());
                streamWriter.writeCharacters("\n    ");
                streamWriter.writeEndElement();
                streamWriter.writeCharacters("\n");
            }
            streamWriter.writeCharacters("\n    ");
            streamWriter.writeEndElement();
            streamWriter.writeEndDocument();
        }

        public void dispose() {
            // Release the lock for this realm identity
            IdentityLock identityLock = lock;
            lock = null;
            if (identityLock != null) {
                identityLock.release();
            }
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            final LoadedIdentity loadedIdentity = loadIdentity(true, false, false);
            return loadedIdentity == null ? AuthorizationIdentity.EMPTY : AuthorizationIdentity.basicIdentity(loadedIdentity.getAttributes());
        }

        /**
         * @param upgradeIdentity skip integrity validation if checking for identity namespace upgrade
         */
        private LoadedIdentity loadIdentity(final boolean skipCredentials, final boolean skipAttributes, final boolean upgradeIdentity) throws RealmUnavailableException {
            if (System.getSecurityManager() == null) {
                return loadIdentityPrivileged(skipCredentials, skipAttributes, upgradeIdentity);
            }
            try {
                return AccessController.doPrivileged((PrivilegedExceptionAction<LoadedIdentity>) () -> loadIdentityPrivileged(skipCredentials, skipAttributes, upgradeIdentity));
            } catch (PrivilegedActionException e) {
                if (e.getException() instanceof RealmUnavailableException) {
                    throw (RealmUnavailableException) e.getException();
                }
                throw new RuntimeException(e.getException());
            }
        }

        protected LoadedIdentity loadIdentityPrivileged(final boolean skipCredentials, final boolean skipAttributes, final boolean upgradeIdentity) throws RealmUnavailableException {
            if (!isIntegrityValid() && !upgradeIdentity) {
                throw new RealmUnavailableException(ElytronMessages.log.invalidIdentitySignature(name));
            }
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

        private LoadedIdentity parseIdentity(final XMLStreamReader streamReader, final boolean skipCredentials, final boolean skipAttributes) throws RealmUnavailableException, XMLStreamException {
            final int tag = streamReader.nextTag();
            Version version;
            if (tag != START_ELEMENT || ((version = identifyVersion(streamReader)) == null) || ! "identity".equals(streamReader.getLocalName())) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }
            return parseIdentityContents(streamReader, version, skipCredentials, skipAttributes);
        }

        private Version identifyVersion(final XMLStreamReader streamReader) {
            return KNOWN_NAMESPACES.get(streamReader.getNamespaceURI());
        }

        private LoadedIdentity parseIdentityContents(final XMLStreamReader streamReader, final Version version, final boolean skipCredentials, final boolean skipAttributes) throws RealmUnavailableException, XMLStreamException {
            final int attributeCount = streamReader.getAttributeCount();
            if (attributeCount > 0) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }
            List<Credential> credentials = Collections.emptyList();
            Attributes attributes = Attributes.EMPTY;
            boolean gotCredentials = false;
            boolean gotAttributes = false;
            boolean upgradeIdentity = false;
            for (;;) {
                if (streamReader.isEndElement()) {
                    if (attributes == Attributes.EMPTY && !skipAttributes) {
                        // Since this could be a use-case wanting to modify the attributes, make sure that we have a
                        // modifiable version of Attributes;
                        attributes = new MapAttributes();
                    }
                    return new LoadedIdentity(name, credentials, attributes, hashEncoding, upgradeIdentity);
                }
                if (!(version.getNamespace().equals(streamReader.getNamespaceURI())) && !(XMLSignature.XMLNS.equals(streamReader.getNamespaceURI()))) {
                    // Mixed versions unsupported.
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }

                if("identity".equals(streamReader.getLocalName())) {
                    if (!version.isAtLeast(Version.VERSION_1_2) && integrityEnabled) {
                        upgradeIdentity = true;
                    }
                }
                if ("principal".equals(streamReader.getLocalName())) {
                    if (version.isAtLeast(Version.VERSION_1_2)) {
                        consumeContent(streamReader);
                    } else {
                        throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                    }
                }
                // Warning if integrity enabled on existing realm before ELY-2491 fix: https://issues.redhat.com/browse/ELY-2491
                if ("Signature".equals(streamReader.getLocalName())) {
                    if (! version.isAtLeast(Version.VERSION_1_2)) {
                        ElytronMessages.log.warnv("Identity at %s contains a signature, but identity version does not support integrity verification." +
                                " This identity will be rewritten into a valid version.", path);
                        upgradeIdentity = true;
                    }
                }

                if (! gotCredentials && "credentials".equals(streamReader.getLocalName())) {
                    gotCredentials = true;
                    if (skipCredentials) {
                        consumeContent(streamReader);
                    } else {
                        credentials = parseCredentials(streamReader, version);
                    }
                } else if (! gotAttributes && "attributes".equals(streamReader.getLocalName())) {
                    gotAttributes = true;
                    if (skipAttributes) {
                        consumeContent(streamReader);
                    } else {
                        attributes = parseAttributes(streamReader, version);
                    }
                }
                streamReader.nextTag();
            }
        }

        private List<Credential> parseCredentials(final XMLStreamReader streamReader, final Version version) throws RealmUnavailableException, XMLStreamException {
            final int attributeCount = streamReader.getAttributeCount();
            if (attributeCount > 0) {
                throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
            }
            if (streamReader.nextTag() == END_ELEMENT) {
                return Collections.emptyList();
            }
            List<Credential> credentials = new ArrayList<>();
            do {
                if (! version.getNamespace().equals(streamReader.getNamespaceURI()) ) {
                    // Mixed versions unsupported.
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
                if ("password".equals(streamReader.getLocalName())) {
                    parsePassword(credentials, streamReader, version);
                } else if ("public-key".equals(streamReader.getLocalName())) {
                    parsePublicKey(credentials, streamReader);
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
            function.parseCredential(algorithm, format, text);
        }

        private void parseCertificate(final List<Credential> credentials, final XMLStreamReader streamReader) throws RealmUnavailableException, XMLStreamException {
            parseCredential(streamReader, (algorithm, format, text) -> {
                if (algorithm == null) algorithm = X509_FORMAT;
                if (format == null) format = X509_FORMAT;
                try {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance(algorithm);
                    credentials.add(new X509CertificateChainPublicCredential((X509Certificate) certificateFactory.generateCertificate(
                        CodePointIterator.ofString(text).base64Decode().asInputStream())));
                } catch (CertificateException | ClassCastException e) {
                    throw ElytronMessages.log.fileSystemRealmCertificateReadError(format, path, streamReader.getLocation().getLineNumber(), name);
                }
            });
        }

        private void parsePublicKey(final List<Credential> credentials, final XMLStreamReader streamReader) throws RealmUnavailableException, XMLStreamException {
            parseCredential(streamReader, (algorithm, format, text) -> {
                if (algorithm == null) {
                    throw ElytronMessages.log.fileSystemRealmMissingAttribute("algorithm", path, streamReader.getLocation().getLineNumber(), name);
                }
                if (format == null) {
                    format = X509_FORMAT;
                } else if (!X509_FORMAT.equals(format)) {
                    throw ElytronMessages.log.fileSystemRealmUnsupportedKeyFormat(format, path, streamReader.getLocation().getLineNumber(), name);
                }
                try {
                    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                    credentials.add(new PublicKeyCredential(keyFactory.generatePublic(new PKCS8EncodedKeySpec(CodePointIterator.ofString(text).base64Decode().drain()))));
                } catch (NoSuchAlgorithmException e) {
                    throw ElytronMessages.log.fileSystemRealmUnsupportedKeyAlgorithm(format, path, streamReader.getLocation().getLineNumber(), name, e);
                } catch (InvalidKeySpecException e) {
                    throw ElytronMessages.log.fileSystemRealmUnsupportedKeyFormat(format, path, streamReader.getLocation().getLineNumber(), name);
                }
            });
        }

        private void parsePassword(final List<Credential> credentials, final XMLStreamReader streamReader, final Version version) throws XMLStreamException, RealmUnavailableException {
            parseCredential(streamReader, (algorithm, format, text) -> {
                try {
                    if (ENCRYPTION_FORMAT.equals(format)) {
                        if (! version.isAtLeast(Version.VERSION_1_1)) {
                            throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                        }
                        if (algorithm == null) {
                            throw ElytronMessages.log.fileSystemRealmMissingAttribute("algorithm", path, streamReader.getLocation().getLineNumber(), name);
                        }
                        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm, providers);
                        byte[] encryptedPasswordBytes = CodePointIterator.ofChars(text.toCharArray()).base64Decode().drain();
                        byte[] decryptedPasswordBytes;
                        try {
                            decryptedPasswordBytes = CipherUtil.decrypt(encryptedPasswordBytes, secretKey);
                        } catch (GeneralSecurityException e) {
                            throw ElytronMessages.log.fileSystemRealmDecryptionFailed(e);
                        }
                        PasswordSpec passwordSpec = BasicPasswordSpecEncoding.decode(decryptedPasswordBytes);

                        if (passwordSpec != null) {
                            credentials.add(new PasswordCredential(passwordFactory.generatePassword(passwordSpec)));
                        } else {
                            throw ElytronMessages.log.fileSystemRealmInvalidPasswordAlgorithm(algorithm, path, streamReader.getLocation().getLineNumber(), name);
                        }
                    } else if (BASE64_FORMAT.equals(format) || HEX.equals(format)) {
                        if (algorithm == null) {
                            throw ElytronMessages.log.fileSystemRealmMissingAttribute("algorithm", path, streamReader.getLocation().getLineNumber(), name);
                        }
                        PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm, providers);
                        byte[] passwordBytes;
                        if (BASE64_FORMAT.equals(format)) {
                            passwordBytes = CodePointIterator.ofChars(text.toCharArray()).base64Decode().drain();
                        } else {
                            passwordBytes = CodePointIterator.ofChars(text.toCharArray()).hexDecode().drain();
                        }
                        PasswordSpec passwordSpec = BasicPasswordSpecEncoding.decode(passwordBytes);

                        if (passwordSpec != null) {
                            credentials.add(new PasswordCredential(passwordFactory.generatePassword(passwordSpec)));
                        } else {
                            throw ElytronMessages.log.fileSystemRealmInvalidPasswordAlgorithm(algorithm, path, streamReader.getLocation().getLineNumber(), name);
                        }
                    } else if (MCF_FORMAT.equals(format)) {
                        credentials.add(new PasswordCredential(ModularCrypt.decode(text)));
                    } else {
                        throw ElytronMessages.log.fileSystemRealmInvalidPasswordFormat(format, path, streamReader.getLocation().getLineNumber(), name);
                    }
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    throw ElytronMessages.log.fileSystemRealmInvalidContent(path, streamReader.getLocation().getLineNumber(), name);
                }
            });
        }

        private void parseOtp(final List<Credential> credentials, final XMLStreamReader streamReader) throws XMLStreamException, RealmUnavailableException {
            String name = null;
            String algorithm = null;
            byte[] hash = null;
            String seed = null;
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
                    hash = CodePointIterator.ofString(streamReader.getAttributeValue(i)).base64Decode(Base64Alphabet.STANDARD, false).drain();
                } else if ("seed".equals(localName)) {
                    seed = new String(CodePointIterator.ofString(streamReader.getAttributeValue(i)).base64Decode(Base64Alphabet.STANDARD, false).drain(), StandardCharsets.US_ASCII);
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
                if (algorithm == null) {
                    throw ElytronMessages.log.fileSystemRealmMissingAttribute("algorithm", path, streamReader.getLocation().getLineNumber(), name);
                }
                PasswordFactory passwordFactory = PasswordFactory.getInstance(algorithm, providers);
                Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(hash, seed, sequenceNumber));
                credentials.add(new PasswordCredential(password));
            } catch (InvalidKeySpecException e) {
                throw ElytronMessages.log.fileSystemRealmInvalidOtpDefinition(path, streamReader.getLocation().getLineNumber(), name, e);
            } catch (NoSuchAlgorithmException e) {
                throw ElytronMessages.log.fileSystemRealmInvalidOtpAlgorithm(algorithm, path, streamReader.getLocation().getLineNumber(), name, e);
            }
        }

        private Attributes parseAttributes(final XMLStreamReader streamReader, final Version version) throws RealmUnavailableException, XMLStreamException {
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
                if (! version.getNamespace().equals(streamReader.getNamespaceURI()) ) {

                    // Mixed versions unsupported.
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
            if (secretKey != null) {
                try {
                    attributes.addLast(CipherUtil.decrypt(name, secretKey), CipherUtil.decrypt(value, secretKey));
                } catch (GeneralSecurityException e){
                    throw ElytronMessages.log.fileSystemRealmDecryptionFailed(e);
                }
            } else {
                attributes.addLast(name, value);
            }
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

        private boolean isIntegrityValid() {
            if (this.publicKey != null) {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                Document doc;
                try {
                    doc = dbf.newDocumentBuilder().parse(path.toString());
                } catch (SAXException | IOException | ParserConfigurationException e) {
                    return false;
                }
                return (validatePrincipalName(doc) && validateDigitalSignature(doc));
            }
            return true;
        }

        // Process for updating identity:
        // 1. Validate current identity digital signature
        // 2. Update identity with new data
        // 3. Create new digital signature
        private boolean validateDigitalSignature(Document doc) {
            try {
                NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
                if (nl.getLength() == 0) {
                    throw ElytronMessages.log.cannotFindSignature(path.toString());
                }
                XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
                DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
                XMLSignature signature = fac.unmarshalXMLSignature(valContext);
                boolean coreValidity = signature.validate(valContext);
                ElytronMessages.log.tracef("FileSystemSecurityRealm - verification against signature for credential [%s] = %b", name, coreValidity);
                return coreValidity;
           } catch (IOException | MarshalException | XMLSignatureException e) {
                ElytronMessages.log.tracef("FileSystemSecurityRealm - Error during verification. Signature for credential [%s] failed", name);
                return false;
            }
        }

        private boolean validatePrincipalName(Document doc) {
            NodeList nl = doc.getElementsByTagName("principal");
            if (nl.getLength() == 0) {
                ElytronMessages.log.tracef("FileSystemSecurityRealm - verification against principal for credential [%s] = %b", name, false);
                return false;
            }
            String principalName = nl.item(0).getAttributes().getNamedItem("name").getNodeValue();
            if (secretKey != null) {
                try {
                    principalName = CipherUtil.decrypt(principalName, secretKey);
                } catch (GeneralSecurityException e) {
                    ElytronMessages.log.tracef("FileSystemSecurityRealm - verification against principal for credential [%s] = %b", name, false);
                    return false;
                }
            }
            boolean validity = Objects.equals(principalName, name);
            ElytronMessages.log.tracef("FileSystemSecurityRealm - verification against principal for credential [%s] = %b", name, validity);
            return validity;
        }

        /**
         * Writes a signed hash of the identity to file. If the identity does nto currently support integrity
         * verification, it is rewritten in the {@link Version#VERSION_1_2 VERSION_1_2} namespace.
         *
         * @param identityUpgradeRunning skips identity version check if true (upgrade is currently running)
         */
        private void writeDigitalSignature(Path path, String name, boolean identityUpgradeRunning) throws RealmUnavailableException {
            try {
                if (!identityUpgradeRunning) {
                    LoadedIdentity loadedIdentity = loadIdentity(false, false, true);
                    try {
                        if (loadedIdentity.getUpgradeIdentity()) {
                            replaceIdentity(loadedIdentity);
                        }
                    } catch (NullPointerException ignored) {}
                }

                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder builder = dbf.newDocumentBuilder();
                Document doc = builder.parse(Files.newInputStream(path));
                Element elem = doc.getDocumentElement();
                NodeList signatureNode = doc.getElementsByTagName("Signature");
                if (signatureNode.getLength() > 0) {
                    Node sig = signatureNode.item(0);
                    elem.removeChild(sig);
                }
                DOMSignContext dsc = new DOMSignContext(this.privateKey, elem);
                XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
                Reference ref = fac.newReference
                        ("", fac.newDigestMethod(DigestMethod.SHA256, null),
                                Collections.singletonList
                                        (fac.newTransform(Transform.ENVELOPED,
                                                (TransformParameterSpec) null)), null, null);
                String signatureMethod = "";
                // https://issues.redhat.com/browse/ELY-2346
                // Once JDK 8 support is removed use the javax.xml.crypto.dsig.SignatureMethod to set these signatureMethods
                switch (this.publicKey.getAlgorithm()) {
                    case "DSA":
                        signatureMethod = "http://www.w3.org/2009/xmldsig11#dsa-sha256";
                        break;
                    case "RSA":
                        signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
                        break;
                    case "HMAC":
                        signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
                        break;
                    case "EC":
                        signatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
                        break;
                }
                SignedInfo si = fac.newSignedInfo
                        (fac.newCanonicalizationMethod
                                        (CanonicalizationMethod.INCLUSIVE,
                                                (C14NMethodParameterSpec) null),
                                fac.newSignatureMethod(signatureMethod, null),
                                Collections.singletonList(ref));
                KeyInfoFactory kif = fac.getKeyInfoFactory();
                KeyValue kv = kif.newKeyValue(this.publicKey);
                KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
                XMLSignature signature = fac.newXMLSignature(si, ki);
                signature.sign(dsc);
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                DOMSource source = new DOMSource(doc);
                FileWriter writer = new FileWriter(String.valueOf(path));
                StreamResult result = new StreamResult(writer);
                transformer.transform(source, result);
                ElytronMessages.log.tracef("FileSystemSecurityRealm - signature against file updated [%s]", name);
                writer.close();
            } catch (ParserConfigurationException | IOException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                    KeyException | XMLSignatureException | MarshalException | TransformerException | SAXException e) {
                ElytronMessages.log.tracef("FileSystemSecurityRealm - Error during signature generation against identity [%s]", name);
                throw ElytronMessages.log.unableToGenerateSignature(String.valueOf(this.path));
            }
        }
    }

    protected static final class LoadedIdentity {
        private final String name;
        private final List<Credential> credentials;
        private final Attributes attributes;
        private final Encoding hashEncoding;
        private final boolean upgradeIdentity;

        LoadedIdentity(final String name, final List<Credential> credentials, final Attributes attributes,
                final Encoding hashEncoding, final boolean upgradeIdentity) {
            this.name = name;
            this.credentials = credentials;
            this.attributes = attributes;
            this.hashEncoding = hashEncoding;
            this.upgradeIdentity = upgradeIdentity;
        }

        public String getName() {
            return name;
        }

        public Attributes getAttributes() {
            return attributes;
        }

        List<Credential> getCredentials() {
            return credentials;
        }

        public Encoding getHashEncoding() {
            return hashEncoding;
        }

        public boolean getUpgradeIdentity() {
            return upgradeIdentity;
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

    public static class IntegrityResult {
        /**
         * The result of the integrity check and invalid identities.
         */
        private final boolean valid;
        private final ArrayList<String> identityNames;

        IntegrityResult(final boolean valid, final ArrayList<String> identityNames) {
            this.valid = valid;
            this.identityNames = identityNames;
        }

        /**
         * The validity of the integrity check.
         *
         * @return {@code true} if the integrity check was successful.
         */
        public boolean isValid() {
            return valid;
        }

        /**
         * Returns a string of the identities that were found to be invalid.
         *
         * @return the list of identities that were found to be invalid.
         */
        public String getIdentityNames() {
            return identityNames.toString();
        }
    }
}
