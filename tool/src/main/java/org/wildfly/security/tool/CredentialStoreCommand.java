/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import java.io.IOException;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.SecretKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.util.ElytronFilePasswordProvider;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.credential.store.impl.PropertiesCredentialStore;
import org.wildfly.security.encryption.CipherUtil;
import org.wildfly.security.encryption.SecretKeyUtil;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.ssh.util.SshUtil;

import static org.wildfly.security.tool.Params.ALIAS_PARAM;
import static org.wildfly.security.tool.Params.CREATE_CREDENTIAL_STORE_PARAM;
import static org.wildfly.security.tool.Params.CREDENTIAL_STORE_TYPE_PARAM;
import static org.wildfly.security.tool.Params.CUSTOM_CREDENTIAL_STORE_PROVIDER_PARAM;
import static org.wildfly.security.tool.Params.DEBUG_PARAM;
import static org.wildfly.security.tool.Params.HELP_PARAM;
import static org.wildfly.security.tool.Params.IMPLEMENTATION_PROPERTIES_PARAM;
import static org.wildfly.security.tool.Params.ITERATION_PARAM;
import static org.wildfly.security.tool.Params.OTHER_PROVIDERS_PARAM;
import static org.wildfly.security.tool.Params.PASSWORD_PARAM;
import static org.wildfly.security.tool.Params.SALT_PARAM;
import static org.wildfly.security.tool.Params.STORE_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.SUMMARY_PARAM;

/**
 * Credential Store Command
 * Performs credential store related operations.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class CredentialStoreCommand extends Command {

    public static int ACTION_NOT_DEFINED = 5;
    public static int ALIAS_NOT_FOUND = 6;

    public static final String RSA_ALGORITHM = "RSA";
    public static final String DSA_ALGORITHM = "DSA";
    public static final String EC_ALGORITHM = "EC";

    public static final String CREDENTIAL_STORE_COMMAND = "credential-store";

    public static final String PASSWORD_CREDENTIAL_VALUE_PARAM = "secret";
    public static final String ADD_ALIAS_PARAM = "add";
    public static final String CHECK_ALIAS_PARAM = "exists";
    public static final String ALIASES_PARAM = "aliases";
    public static final String CREDENTIAL_TYPES = "credential-types";
    public static final String REMOVE_ALIAS_PARAM = "remove";
    public static final String ENTRY_TYPE_PARAM = "entry-type";
    public static final String SIZE_PARAM = "size";

    public static final String GENERATE_KEY_PAIR_PARAM = "generate-key-pair";
    public static final String ALGORITHM_PARAM = "algorithm";
    public static final String EXPORT_KEY_PAIR_PUBLIC_KEY_PARAM = "export-key-pair-public-key";
    public static final String IMPORT_KEY_PAIR_PARAM = "import-key-pair";
    public static final String PRIVATE_KEY_LOCATION_PARAM = "private-key-location";
    public static final String PUBLIC_KEY_LOCATION_PARAM = "public-key-location";
    public static final String PRIVATE_KEY_STRING_PARAM = "private-key-string";
    public static final String PUBLIC_KEY_STRING_PARAM = "public-key-string";
    public static final String KEY_PASSPHRASE_PARAM = "key-passphrase";

    public static final String GENERATE_SECRET_KEY = "generate-secret-key";
    public static final String EXPORT_SECRET_KEY = "export-secret-key";
    public static final String IMPORT_SECRET_KEY = "import-secret-key";
    public static final String KEY_PARAM = "key";
    public static final String ENCRYPT = "encrypt";
    public static final String CLEAR_TEXT = "clear-text";
    public static final String ENTRY = "entry";

    private static final List<String> filebasedKeystoreTypes = Collections.unmodifiableList(Arrays.asList("JKS", "JCEKS", "PKCS12"));

    private final Options options;
    private CommandLineParser parser = new DefaultParser();
    private CommandLine cmdLine = null;

    CredentialStoreCommand() {
        options = new Options();
        Option opt = new Option("l", STORE_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdLineStoreLocationDesc());
        opt.setArgName("loc");
        opt.setOptionalArg(false);
        options.addOption(opt);
        opt = new Option("u", IMPLEMENTATION_PROPERTIES_PARAM, true, ElytronToolMessages.msg.cmdLineImplementationPropertiesDesc());
        options.addOption(opt);
        opt = new Option("p", PASSWORD_PARAM, true, ElytronToolMessages.msg.cmdLineCredentialStorePassword());
        opt.setArgName("pwd");
        options.addOption(opt);
        options.addOption("s", SALT_PARAM, true, ElytronToolMessages.msg.cmdLineSaltDesc());
        options.addOption("i", ITERATION_PARAM, true, ElytronToolMessages.msg.cmdLineIterationCountDesc());
        opt = new Option("x", PASSWORD_CREDENTIAL_VALUE_PARAM, true, ElytronToolMessages.msg.cmdLinePasswordCredentialValueDesc());
        opt.setArgName("secret to store");
        opt.setOptionalArg(true);
        options.addOption(opt);
        opt = new Option("n", ENTRY_TYPE_PARAM, true, ElytronToolMessages.msg.cmdLineEntryTypeDesc());
        opt.setArgName("type");
        opt.setOptionalArg(true);
        options.addOption(opt);
        opt = new Option("o", OTHER_PROVIDERS_PARAM, true, ElytronToolMessages.msg.cmdLineOtherProvidersDesc());
        opt.setArgName("providers");
        opt.setOptionalArg(true);
        options.addOption(opt);
        opt = new Option("q", CUSTOM_CREDENTIAL_STORE_PROVIDER_PARAM, true, ElytronToolMessages.msg.cmdLineCustomCredentialStoreProviderDesc());
        opt.setArgName("cs-provider");
        opt.setOptionalArg(true);
        options.addOption(opt);
        options.addOption("c", CREATE_CREDENTIAL_STORE_PARAM, false, ElytronToolMessages.msg.cmdLineCreateCredentialStoreDesc());
        opt = new Option("t", CREDENTIAL_STORE_TYPE_PARAM, true, ElytronToolMessages.msg.cmdLineCredentialStoreTypeDesc());
        opt.setArgName("type");
        options.addOption(opt);
        options.addOption("f", SUMMARY_PARAM, false, ElytronToolMessages.msg.cmdLinePrintSummary());

        options.addOption("j", SIZE_PARAM, true, ElytronToolMessages.msg.cmdLineKeySizeDesc());
        options.addOption("k", ALGORITHM_PARAM, true, ElytronToolMessages.msg.cmdLineKeyAlgorithmDesc());
        options.addOption("kp", KEY_PASSPHRASE_PARAM, true, ElytronToolMessages.msg.cmdLineKeyPassphraseDesc());

        OptionGroup privateKP = new OptionGroup();
        Option privateString = new Option("pvk", PRIVATE_KEY_STRING_PARAM, true, ElytronToolMessages.msg.cmdLinePrivateKeyStringDesc());
        Option privateLocation = new Option("pvl", PRIVATE_KEY_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdLinePrivateKeyLocationDesc());
        privateKP.addOption(privateString);
        privateKP.addOption(privateLocation);
        options.addOptionGroup(privateKP);

        OptionGroup publicKP = new OptionGroup();
        Option publicString = new Option("pbk", PUBLIC_KEY_STRING_PARAM, true, ElytronToolMessages.msg.cmdLinePublicKeyStringDesc());
        Option publicLocation = new Option("pbl", PUBLIC_KEY_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdLinePublicKeyLocationDesc());
        publicKP.addOption(publicString);
        publicKP.addOption(publicLocation);
        options.addOptionGroup(publicKP);

        options.addOption(Option.builder()
                .longOpt(SIZE_PARAM)
                .hasArg()
                .argName("size")
                .desc(ElytronToolMessages.msg.keySize())
                .build());
        options.addOption(Option.builder()
                .longOpt(KEY_PARAM)
                .hasArg()
                .argName("key")
                .desc(ElytronToolMessages.msg.key())
                .build());

        // This pair (clear-text and entry) are mutually exclusive but we will check later.
        options.addOption(Option.builder()
                .longOpt(CLEAR_TEXT)
                .hasArg()
                .argName("clear text")
                .desc(ElytronToolMessages.msg.clearText())
                .build());
        options.addOption(Option.builder()
                .longOpt(ENTRY)
                .hasArg()
                .argName(ALIAS_PARAM)
                .desc(ElytronToolMessages.msg.cmdLineEntryDesc())
                .build());

        OptionGroup og = new OptionGroup(); // Mutually Exclusive Options (Actions)

        Option a = new Option("a", ADD_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineAddAliasDesc());
        a.setArgName("alias");
        Option e = new Option("e", CHECK_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineCheckAliasDesc());
        e.setArgName("alias");
        Option r = new Option("r", REMOVE_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineRemoveAliasDesc());
        r.setArgName("alias");
        Option v = new Option("v", ALIASES_PARAM, false, ElytronToolMessages.msg.cmdLineAliasesDesc());
        Option st = new Option("st", CREDENTIAL_TYPES, true, ElytronToolMessages.msg.cmdLineAliasTypes());
        st.setArgName("alias");
        Option g = new Option("g", GENERATE_KEY_PAIR_PARAM, true, ElytronToolMessages.msg.cmdLineGenerateKeyPairDesc());
        g.setOptionalArg(false);
        g.setArgName("alias");
        Option xp = new Option("xp", EXPORT_KEY_PAIR_PUBLIC_KEY_PARAM, true, ElytronToolMessages.msg.cmdLineExportPublicKeyDesc());
        xp.setOptionalArg(false);
        xp.setArgName("alias");
        Option ikp = new Option("ikp", IMPORT_KEY_PAIR_PARAM, true, ElytronToolMessages.msg.cmdLineImportKeyPairDesc());
        ikp.setOptionalArg(false);
        ikp.setArgName("alias");

        og.addOption(a);
        og.addOption(e);
        og.addOption(r);
        og.addOption(v);
        og.addOption(st);
        og.addOption(g);
        og.addOption(xp);
        og.addOption(ikp);

        og.addOption(Option.builder()
                .longOpt(GENERATE_SECRET_KEY)
                .hasArg()
                .argName(ALIAS_PARAM)
                .desc(ElytronToolMessages.msg.generateSecretKey())
                .build());
        og.addOption(Option.builder()
                .longOpt(EXPORT_SECRET_KEY)
                .hasArg()
                .argName(ALIAS_PARAM)
                .desc(ElytronToolMessages.msg.exportSecretKey())
                .build());
        og.addOption(Option.builder()
                .longOpt(IMPORT_SECRET_KEY)
                .hasArg()
                .argName(ALIAS_PARAM)
                .desc(ElytronToolMessages.msg.importSecretKey())
                .build());
        og.addOption(Option.builder()
                .longOpt(ENCRYPT)
                .hasArg()
                .argName(ALIAS_PARAM)
                .desc(ElytronToolMessages.msg.encrypt())
                .build());


        Option h = new Option("h", HELP_PARAM, false, ElytronToolMessages.msg.cmdLineHelp());
        Option d = new Option("d", DEBUG_PARAM, false, ElytronToolMessages.msg.cmdLineDebug());
        options.addOptionGroup(og);
        options.addOption(h);
        options.addOption(d);
    }

    private static void readAttributesForView(Path path, String prefix, String attributes, Map<String, Object> attrs) {
        try {
            Map<String, Object> newAttrs = Files.readAttributes(path, attributes);
            if (newAttrs != null) {
                for (Map.Entry<String, Object> e : newAttrs.entrySet()) {
                    attrs.put(prefix + e.getKey(), e.getValue());
                }
            }
        } catch (Exception e) {
            // A view can be supported but the operation is later reported
            // as not supported, so just add the attributes if possible.
        }
    }

    /**
     * Reads the attributes that are required to be preserved in the file.
     * The attributes are posix, dos and acl ones that are interested to
     * maintain.
     *
     * @param path The path to get the attributes from
     * @return The map of attributes (not null) with keys prefixed with the type (e.g. "posix:permissions")
     * @throws IOException Some error reading the file attributes
     */
    public static Map<String, Object> readAttributesForPreservation(Path path) throws IOException {
        Map<String, Object> attrs = new HashMap<>();
        if (Files.exists(path)) {
            // copy all the permissions that are going to be maintained (posix, dos and acl)
            Set<String> supportedViews = path.getFileSystem().supportedFileAttributeViews();
            if (supportedViews.contains("posix")) {
                readAttributesForView(path, "posix:", "posix:permissions", attrs);
            }
            if (supportedViews.contains("dos")) {
                readAttributesForView(path, "dos:", "dos:readonly,hidden,archive,system", attrs);
            }
            if (supportedViews.contains("acl")) {
                readAttributesForView(path, "acl:", "acl:acl", attrs);
            }
        }
        return attrs;
    }

    /**
     * Applies over a file all the attributes previously read by the
     * <em>readAttributesForPreservation</em> method.
     *
     * @param path The path to set the attributes to
     * @param attrs The attributes to apply (key should be prefixed with the type of attr, e.g. "posix:permissions")
     * @throws IOException Some error applying the attributes
     */
    public static void setAttributesForPreservation(Path path, Map<String, Object> attrs) throws IOException {
        if (attrs != null && Files.exists(path)) {
            for (Map.Entry<String, Object> attribute : attrs.entrySet()) {
                Files.setAttribute(path, attribute.getKey(), attribute.getValue());
            }
        }
    }

    @Override
    public void execute(String[] args) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        cmdLine = parser.parse(options, args, false);
        setEnableDebug(cmdLine.hasOption(DEBUG_PARAM));
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            return;
        }

        printDuplicatesWarning(cmdLine);

        String location = cmdLine.getOptionValue(STORE_LOCATION_PARAM);
        if ((cmdLine.hasOption(ALIASES_PARAM) || cmdLine.hasOption(CHECK_ALIAS_PARAM) || cmdLine.hasOption(CREDENTIAL_TYPES)) && location != null && !Files.exists(Paths.get(location))) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.storageFileDoesNotExist(location);
        }
        String csPassword = cmdLine.getOptionValue(PASSWORD_PARAM);
        String password = csPassword == null ? "" : csPassword;
        String salt = cmdLine.getOptionValue(SALT_PARAM);
        String csType = cmdLine.getOptionValue(CREDENTIAL_STORE_TYPE_PARAM, KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
        int iterationCount = getArgumentAsInt(cmdLine.getOptionValue(ITERATION_PARAM));
        String entryType = cmdLine.getOptionValue(ENTRY_TYPE_PARAM);
        String otherProviders = cmdLine.getOptionValue(OTHER_PROVIDERS_PARAM);
        String csProvider = cmdLine.getOptionValue(CUSTOM_CREDENTIAL_STORE_PROVIDER_PARAM);
        boolean createStorage = cmdLine.hasOption(CREATE_CREDENTIAL_STORE_PARAM);
        if (createStorage && cmdLine.getArgs().length > 0) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.noArgumentOption(CREATE_CREDENTIAL_STORE_PARAM);
        }
        if (!createStorage && location != null && !Files.exists(Paths.get(location))) {
            throw ElytronToolMessages.msg.locationDoesNotExistCreationDisabled(location);
        }
        boolean printSummary = cmdLine.hasOption(SUMMARY_PARAM);
        String secret = cmdLine.getOptionValue(PASSWORD_CREDENTIAL_VALUE_PARAM);
        String key = cmdLine.getOptionValue(KEY_PARAM);

        int size = getArgumentAsInt(cmdLine.getOptionValue(SIZE_PARAM), 256);

        Map<String, String> implProps = parseCredentialStoreProperties(cmdLine.getOptionValue(IMPLEMENTATION_PROPERTIES_PARAM));

        CredentialStore credentialStore;
        if (csProvider != null) {
            credentialStore = CredentialStore.getInstance(csType, csProvider, getProvidersSupplier(csProvider));
        } else {
            try {
                credentialStore = CredentialStore.getInstance(csType);
            } catch (NoSuchAlgorithmException e) {
                // fallback to load all possible providers
                credentialStore = CredentialStore.getInstance(csType, getProvidersSupplier(null));
            }
        }
        implProps.put("location", location);
        implProps.putIfAbsent("modifiable", Boolean.TRUE.toString());
        implProps.putIfAbsent("create", Boolean.valueOf(createStorage).toString());
        if (csType.equals(KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE)) {
            implProps.putIfAbsent("keyStoreType", "JCEKS");
        }
        String implPropsKeyStoreType = implProps.get("keyStoreType");
        if (location == null && implPropsKeyStoreType != null && filebasedKeystoreTypes.contains(implPropsKeyStoreType.toUpperCase(Locale.ENGLISH))) {
            throw ElytronToolMessages.msg.filebasedKeystoreLocationMissing(implPropsKeyStoreType);
        }

        CredentialStore.CredentialSourceProtectionParameter credentialSourceProtectionParameter = null;
        if (csPassword == null && !PropertiesCredentialStore.NAME.equals(csType)) {
            // prompt for password
            csPassword = prompt(false, ElytronToolMessages.msg.credentialStorePasswordPrompt(), createStorage, ElytronToolMessages.msg.credentialStorePasswordPromptConfirm());
            if (csPassword == null) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw ElytronToolMessages.msg.optionNotSpecified(PASSWORD_PARAM);
            }
        }
        if (csPassword != null) {
            char[] passwordCredential;
            if (csPassword.startsWith("MASK-")) {
                passwordCredential = MaskCommand.decryptMasked(csPassword);
            } else {
                passwordCredential = csPassword.toCharArray();
            }
            credentialSourceProtectionParameter = new CredentialStore.CredentialSourceProtectionParameter(
                            IdentityCredentials.NONE.withCredential(
                                    new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, passwordCredential))));
        }
        credentialStore.initialize(implProps,
                credentialSourceProtectionParameter,
                getProvidersSupplier(otherProviders).get());

        // ELY-1294 compute password to validate salt parameter without --summary.
        if (csPassword != null && !csPassword.startsWith("MASK-") && salt != null && iterationCount > -1) {
            password = MaskCommand.computeMasked(csPassword, salt, iterationCount);
        }

        String cipherTextToken = null;
        if (cmdLine.hasOption(ADD_ALIAS_PARAM)) {
            addAlias(secret, credentialStore, entryType, location);
        } else if (cmdLine.hasOption(REMOVE_ALIAS_PARAM)) {
            removeAlias(credentialStore, entryType, csType);
        } else if (cmdLine.hasOption(CHECK_ALIAS_PARAM)) {
            checkAlias(credentialStore, entryType, csType);
        } else if (cmdLine.hasOption(ALIASES_PARAM)) {
            aliases(credentialStore);
        } else if (cmdLine.hasOption(CREDENTIAL_TYPES)) {
            aliasCredentialTypes(credentialStore);
        } else if (cmdLine.hasOption(GENERATE_KEY_PAIR_PARAM)) {
            generateKeyPair(credentialStore);
        } else if (cmdLine.hasOption(EXPORT_KEY_PAIR_PUBLIC_KEY_PARAM)) {
            exportKeyPairPublicKey(credentialStore, entryType);
        } else if (cmdLine.hasOption(IMPORT_KEY_PAIR_PARAM)) {
            importKeyPair(credentialStore);
        } else if (cmdLine.hasOption(GENERATE_SECRET_KEY)) {
            generateSecretKey(credentialStore, entryType, size);
        } else if (cmdLine.hasOption(EXPORT_SECRET_KEY)) {
            exportSecretKey(credentialStore);
        } else if (cmdLine.hasOption(IMPORT_SECRET_KEY)) {
            importSecretKey(credentialStore, entryType, key);
        } else if (cmdLine.hasOption(ENCRYPT)) {
            cipherTextToken = encrypt(credentialStore);
        } else if (cmdLine.hasOption(CREATE_CREDENTIAL_STORE_PARAM)) {
            //this must be always the last available option as it is not contained within the
            // OptionGroup so could be combined with another command or specified on it's own.
            createCredentialStore(credentialStore);
        } else {
            setStatus(ACTION_NOT_DEFINED);
            throw ElytronToolMessages.msg.actionToPerformNotDefined();
        }

        if (printSummary) {
            StringBuilder com = new StringBuilder();

            if (cmdLine.hasOption(ADD_ALIAS_PARAM)) {
                if (implProps.get("create") != null && implProps.get("create").equals("true")) {
                    getCreateDefaultSummary(implProps, com, password);
                    com.append("\n");
                }
                com.append("/subsystem=elytron/credential-store=test:add-alias(alias=");
                com.append(cmdLine.getOptionValue(ADD_ALIAS_PARAM));
                if (entryType != null) {
                    com.append(",entry-type=\"").append(entryType).append("\"");
                }
                com.append(",secret-value=\"");
                com.append(secret);
                com.append("\")");

            } else if (cmdLine.hasOption(REMOVE_ALIAS_PARAM)) {

                com.append("/subsystem=elytron/credential-store=test:remove-alias(alias=");
                com.append(cmdLine.getOptionValue(REMOVE_ALIAS_PARAM));
                com.append(")");

            } else if (cmdLine.hasOption(ALIASES_PARAM) || cmdLine.hasOption(CHECK_ALIAS_PARAM) ) {
                com.append("/subsystem=elytron/credential-store=test:read-aliases()");
            } else if (cmdLine.hasOption(ENCRYPT) && cipherTextToken != null) {
                getUseExpressionExample(com, cipherTextToken);
            } else if (cmdLine.hasOption(CREATE_CREDENTIAL_STORE_PARAM)){
                if (PropertiesCredentialStore.NAME.equals(csType)) {
                    getCreatePropertiesCredentialStoreSummary(com, location);
                } else {
                    getCreateDefaultSummary(implProps, com, password);
                }
            }

            System.out.println(ElytronToolMessages.msg.commandSummary(com.toString()));
        }
    }

    private void addAlias(String secret, CredentialStore credentialStore, String entryType, String location) throws Exception {
        String alias = cmdLine.getOptionValue(ADD_ALIAS_PARAM);
        if (alias.length() == 0) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(ADD_ALIAS_PARAM);
        }
        if (secret == null) {
            // prompt for secret
            secret = prompt(false, ElytronToolMessages.msg.secretToStorePrompt(), true, ElytronToolMessages.msg.secretToStorePromptConfirm());
            if (secret == null) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw ElytronToolMessages.msg.optionNotSpecified(PASSWORD_CREDENTIAL_VALUE_PARAM);
            }
        }

        // Get the original attributes of the credential store
        Map<String, Object> locationAttributes = null;
        if (location != null) {
            locationAttributes = readAttributesForPreservation(Paths.get(location));
        }

        credentialStore.store(alias, createCredential(secret, entryType));
        credentialStore.flush();
        if (entryType != null) {
            System.out.println(ElytronToolMessages.msg.aliasStored(alias, entryType));
        } else {
            System.out.println(ElytronToolMessages.msg.aliasStored(alias));
        }
        setStatus(ElytronTool.ElytronToolExitStatus_OK);

        // Restore the original attributes of the credential store
        if (location != null) {
            setAttributesForPreservation(Paths.get(location), locationAttributes);
        }
    }

    private void removeAlias(CredentialStore credentialStore, String entryType, String storeType) throws Exception {
        String alias = cmdLine.getOptionValue(REMOVE_ALIAS_PARAM);
        Class<? extends Credential> credClazz = entryTypeToCredential(entryType, storeType);
        if (credentialStore.exists(alias, credClazz)) {
            credentialStore.remove(alias, credClazz);
            credentialStore.flush();
            if (entryType != null) {
                System.out.println(ElytronToolMessages.msg.aliasRemoved(alias, entryType));
            } else {
                System.out.println(ElytronToolMessages.msg.aliasRemoved(alias));
            }
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else {
            if (entryType != null) {
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias, entryType));
            } else {
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
            }
            setStatus(ALIAS_NOT_FOUND);
        }
    }

    private void checkAlias(CredentialStore credentialStore, String entryType, String storeType) throws Exception {
        String alias = cmdLine.getOptionValue(CHECK_ALIAS_PARAM);
        if (credentialStore.exists(alias, entryTypeToCredential(entryType, storeType))) {
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            System.out.println(ElytronToolMessages.msg.aliasExists(alias));
        } else {
            setStatus(ALIAS_NOT_FOUND);
            if (entryType != null) {
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias, entryType));
            } else {
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
            }
        }
    }

    private void aliases(CredentialStore credentialStore) throws Exception {
        Set<String> aliases = credentialStore.getAliases();
        if (aliases.size() != 0) {
            StringBuilder list = new StringBuilder();
            for (String alias: aliases) {
                list.append(alias).append(" ");
            }
            System.out.println(ElytronToolMessages.msg.aliases(list.toString()));
        } else {
            System.out.println(ElytronToolMessages.msg.noAliases());
        }
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
    }

    private void aliasCredentialTypes(CredentialStore credentialStore) {
        String alias = cmdLine.getOptionValue(CREDENTIAL_TYPES);
        Set<String> types = credentialStore.getCredentialTypesForAlias(alias);
        if (types.size() != 0) {
            StringBuilder list = new StringBuilder();
            for (String type: types) {
                list.append(" ").append(type);
            }
            System.out.println(ElytronToolMessages.msg.types(list.toString(), alias));
        } else {
            System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
        }
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
    }

    private void generateKeyPair(CredentialStore credentialStore) throws Exception {
        String alias = cmdLine.getOptionValue(GENERATE_KEY_PAIR_PARAM);
        if (alias == null || alias.isEmpty()) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(GENERATE_KEY_PAIR_PARAM);
        }
        int size = getArgumentAsInt(cmdLine.getOptionValue(SIZE_PARAM));
        String algorithm = cmdLine.getOptionValue(ALGORITHM_PARAM);
        if (algorithm == null) algorithm = RSA_ALGORITHM;
        credentialStore.store(alias, createKeyPairCredential(algorithm, size));
        credentialStore.flush();
        System.out.println(ElytronToolMessages.msg.aliasStored(alias, KeyPairCredential.class.getName()));
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
    }

    private void exportKeyPairPublicKey(CredentialStore credentialStore, String entryType) throws Exception {
        String alias = cmdLine.getOptionValue(EXPORT_KEY_PAIR_PUBLIC_KEY_PARAM);
        if (alias == null || alias.isEmpty()) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(EXPORT_KEY_PAIR_PUBLIC_KEY_PARAM);
        }
        if (credentialStore.exists(alias, KeyPairCredential.class)) {
            KeyPairCredential credential = credentialStore.retrieve(alias, KeyPairCredential.class);
            System.out.println(PublicKeyEntry.toString(credential.getKeyPair().getPublic()));
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else {
            setStatus(ALIAS_NOT_FOUND);
            if (entryType != null) {
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias, entryType));
            } else {
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
            }
        }
    }

    private void importKeyPair(CredentialStore credentialStore) throws Exception {
        String alias = cmdLine.getOptionValue(IMPORT_KEY_PAIR_PARAM);
        if (alias == null || alias.isEmpty()) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(IMPORT_KEY_PAIR_PARAM);
        }

        String passphrase = cmdLine.getOptionValue(KEY_PASSPHRASE_PARAM);
        if (passphrase == null || passphrase.isEmpty()) {
            // prompt for passphrase
            passphrase = prompt(false, ElytronToolMessages.msg.keyPassphrasePrompt(), true, ElytronToolMessages.msg.keyPassphrasePromptConfirm());
        }
        ElytronFilePasswordProvider passwordProvider = new ElytronFilePasswordProvider(createCredential(passphrase, PasswordCredential.class.getName()));

        KeyPairCredential keyPairCredential;
        String privateKeyContent;
        String publicKeyContent = null;
        String privateKeyString = cmdLine.getOptionValue(PRIVATE_KEY_STRING_PARAM);
        String publicKeyString = cmdLine.getOptionValue(PUBLIC_KEY_STRING_PARAM);
        String privateKeyFile = cmdLine.getOptionValue(PRIVATE_KEY_LOCATION_PARAM);
        String publicKeyFile = cmdLine.getOptionValue(PUBLIC_KEY_LOCATION_PARAM);

        if (privateKeyFile != null) {
            if (!Files.exists(Paths.get(privateKeyFile))) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw ElytronToolMessages.msg.keyFileDoesNotExist(privateKeyFile);
            }
            File keyFile = new File(privateKeyFile);
            FileInputStream stream = null;
            byte[] keyData = null;
            try {
                stream = new FileInputStream(keyFile);
                keyData = new byte[stream.available()];
                stream.read(keyData, 0, stream.available());
            } finally {
                safeClose(stream);
            }
            privateKeyContent = new String(keyData);
        } else if (privateKeyString != null) {
            privateKeyContent = privateKeyString;
        } else {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.noPrivateKeySpecified();
        }

        if (privateKeyContent.isEmpty()) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.noPrivateKeySpecified();
        }

        if (publicKeyFile != null) {
            if (!Files.exists(Paths.get(publicKeyFile))) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw ElytronToolMessages.msg.keyFileDoesNotExist(publicKeyFile);
            }
            File keyFile = new File(publicKeyFile);
            FileInputStream stream = null;
            byte[] keyData = null;
            try {
                stream = new FileInputStream(keyFile);
                keyData = new byte[stream.available()];
                stream.read(keyData, 0, stream.available());
            } finally {
                safeClose(stream);
            }
            publicKeyContent = new String(keyData);
        } else if (publicKeyString != null) {
            publicKeyContent = publicKeyString;
        }

        keyPairCredential = parseKeyPairCredential(privateKeyContent, publicKeyContent, passwordProvider);
        credentialStore.store(alias, keyPairCredential);
        credentialStore.flush();
        System.out.println(ElytronToolMessages.msg.aliasStored(alias, KeyPairCredential.class.getName()));
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
    }

    private void generateSecretKey(CredentialStore credentialStore, String entryType, int size) throws Exception {
        String alias = cmdLine.getOptionValue(GENERATE_SECRET_KEY);
        if (alias.length() == 0) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(ALIAS_PARAM);
        }

        final SecretKey secretKey;

        try {
            secretKey = SecretKeyUtil.generateSecretKey(size);
        } catch (Exception e) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw e;
        }

        credentialStore.store(alias, createCredential(secretKey, entryType));
        credentialStore.flush();
        if (entryType != null) {
            System.out.println(ElytronToolMessages.msg.aliasStored(alias, entryType));
        } else {
            System.out.println(ElytronToolMessages.msg.aliasStored(alias));
        }
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
    }

    private void exportSecretKey(CredentialStore credentialStore) throws Exception {
        String alias = cmdLine.getOptionValue(EXPORT_SECRET_KEY);
        if (alias.length() == 0) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(ALIAS_PARAM);
        }

        if (credentialStore.exists(alias, SecretKeyCredential.class)) {
            final SecretKey secretKey = credentialStore.retrieve(alias, SecretKeyCredential.class).getSecretKey();
            final String encoded = SecretKeyUtil.exportSecretKey(secretKey);
            System.out.println(ElytronToolMessages.msg.exportedSecretKey(alias, encoded));
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else {
            setStatus(ALIAS_NOT_FOUND);
            System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
        }
    }

    private void importSecretKey(CredentialStore credentialStore, String entryType, String key) throws Exception {
        String alias = cmdLine.getOptionValue(IMPORT_SECRET_KEY);
        if (alias.length() == 0) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(ALIAS_PARAM);
        }

        if (key == null) {
            // prompt for secret
            key = prompt(true, ElytronToolMessages.msg.keyToImport(), false, null);
            if (key == null) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw ElytronToolMessages.msg.optionNotSpecified(KEY_PARAM);
            }
        }

        final SecretKey secretKey;

        try {
            secretKey = SecretKeyUtil.importSecretKey(key);
        } catch (Exception e) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw e;
        }

        credentialStore.store(alias, createCredential(secretKey, entryType));
        credentialStore.flush();
        if (entryType != null) {
            System.out.println(ElytronToolMessages.msg.aliasStored(alias, entryType));
        } else {
            System.out.println(ElytronToolMessages.msg.aliasStored(alias));
        }
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
    }

    private String encrypt(CredentialStore credentialStore) throws Exception {
        String alias = cmdLine.getOptionValue(ENCRYPT);
        if (alias.length() == 0) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.optionNotSpecified(ALIAS_PARAM);
        }

        String cipherTextToken = null;
        if (credentialStore.exists(alias, SecretKeyCredential.class)) {
            final SecretKey secretKey = credentialStore.retrieve(alias, SecretKeyCredential.class).getSecretKey();

            String clearText = cmdLine.getOptionValue(CLEAR_TEXT);
            String entry = cmdLine.getOptionValue(ENTRY);
            if (clearText != null && entry != null) {
                throw ElytronToolMessages.msg.mutuallyExclusiveOptions(CLEAR_TEXT, ENTRY);
            }

            if (entry != null) {
                if (credentialStore.exists(entry, PasswordCredential.class)) {
                    final Password password = credentialStore.retrieve(entry, PasswordCredential.class).getPassword();
                    if (password instanceof ClearPassword) {
                        clearText = new String(((ClearPassword) password).getPassword());
                    } else {
                        setStatus(ALIAS_NOT_FOUND);
                        System.out.println(ElytronToolMessages.msg.passwordCredentialNotClearText());
                        return null;
                    }
                } else {
                    setStatus(ALIAS_NOT_FOUND);
                    System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
                    return null;
                }
            } else if (clearText == null) {
                clearText = prompt(false, ElytronToolMessages.msg.clearTextToImport(), true, ElytronToolMessages.msg.clearTextToImportAgain());
            }

            cipherTextToken = CipherUtil.encrypt(clearText, secretKey);
            System.out.println(ElytronToolMessages.msg.encryptedToken(cipherTextToken, alias));

            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else {
            setStatus(ALIAS_NOT_FOUND);
            System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
        }

        return cipherTextToken;
    }

    private void createCredentialStore(CredentialStore credentialStore) throws Exception {
        credentialStore.flush();
        System.out.println(ElytronToolMessages.msg.credentialStoreCreated());
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
    }

    private Credential createCredential(final String secret, String entryType) {
        if (entryType == null || PasswordCredential.class.getSimpleName().equals(entryType) || PasswordCredential.class.getName().equals(entryType)) {
            return new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret.toCharArray()));
        } else {
            throw ElytronToolMessages.msg.unknownEntryType(entryType);
        }
    }

    private KeyPairCredential createKeyPairCredential(String algorithm, int size) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator;

        switch (algorithm) {
            case RSA_ALGORITHM: {
                /* Size must range from 512 to 16384. Default size: 2048
                 * see: https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html#GUID-7093246A-31A3-4304-AC5F-5FB6400405E2
                 */
                size = (512 <= size && size <= 16384) ? size : 2048;
                break;
            }
            case DSA_ALGORITHM: {
                /* Size must be multiple of 64 ranging from 512 to 1024, plus 2048 and 3072. Default size: 2048
                 * see: https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html#GUID-3A80CC46-91E1-4E47-AC51-CB7B782CEA7D
                 */
                size = (512 <= size && size <= 1024 && (size % 64) == 0) || size == 2048  || size == 3072 ? size : 2048;
                break;
            }
            case EC_ALGORITHM: {
                /* Size must range from 112 to 571. Default size: 256
                 * see: https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html#GUID-091BF58C-82AB-4C9C-850F-1660824D5254
                 */
                size = (112 <= size && size <= 571) ? size : 256;
                break;
            }
            default: {
                algorithm = RSA_ALGORITHM;
                size = 2048;
                break;
            }
        }

        try {
             keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw ElytronToolMessages.msg.unknownKeyPairAlgorithm(algorithm);
        }
        try {
            keyPairGenerator.initialize(size, new SecureRandom());
        } catch (InvalidParameterException e) {
            throw ElytronToolMessages.msg.invalidKeySize(e.getMessage());
        }
        KeyPairCredential keyPairCredential = new KeyPairCredential(keyPairGenerator.generateKeyPair());
        return keyPairCredential;
    }

    private KeyPairCredential parseKeyPairCredential(String privateKeyContent, String publicKeyContent, FilePasswordProvider passwordProvider) throws Exception {
        KeyPair keyPair;
        try {
            keyPair = SshUtil.parsePemOpenSSHContent(CodePointIterator.ofString(privateKeyContent), passwordProvider).next().tryCast(KeyPair.class);
            if (keyPair == null) throw ElytronToolMessages.msg.xmlNoPemContent();
        } catch (IllegalArgumentException e) {
            if (publicKeyContent == null || publicKeyContent.isEmpty()) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw ElytronToolMessages.msg.noPublicKeySpecified();
            }
            PrivateKey privateKey = Pem.parsePemContent(CodePointIterator.ofString(privateKeyContent)).next().tryCast(PrivateKey.class);
            if (privateKey == null) throw ElytronToolMessages.msg.xmlNoPemContent();
            PublicKey publicKey = Pem.parsePemContent(CodePointIterator.ofString(publicKeyContent)).next().tryCast(PublicKey.class);
            if (publicKey == null) throw ElytronToolMessages.msg.xmlNoPemContent();
            keyPair = new KeyPair(publicKey, privateKey);
        }
        return new KeyPairCredential(keyPair);
    }

    private Credential createCredential(final SecretKey secretKey, String entryType) {
        if (entryType == null || SecretKeyCredential.class.getSimpleName().equals(entryType) || SecretKeyCredential.class.getName().equals(entryType)) {
            return new SecretKeyCredential(secretKey);
        } else {
            throw ElytronToolMessages.msg.unknownEntryType(entryType);
        }
    }

    private Class<? extends Credential> entryTypeToCredential(String entryType, String storeType) {
        if (entryType == null) {
            return defaultCredentialType(storeType);
        } else if (PasswordCredential.class.getSimpleName().equals(entryType) || PasswordCredential.class.getName().equals(entryType)) {
            return PasswordCredential.class;
        } else if (KeyPairCredential.class.getName().equals(entryType)) {
          return KeyPairCredential.class;
        } else if (SecretKeyCredential.class.getSimpleName().equals(entryType) || SecretKeyCredential.class.getName().equals(entryType)) {
            return SecretKeyCredential.class;
        } else {
            throw ElytronToolMessages.msg.unknownEntryType(entryType);
        }
    }

    private static Class<? extends Credential> defaultCredentialType(String storeType) {
        if (PropertiesCredentialStore.NAME.equals(storeType)) {
            return SecretKeyCredential.class;
        }
        return PasswordCredential.class;
    }

    @Override
    protected Set<String> aliases() {
        return Stream.of("cs", "credstore").collect(Collectors.toSet());
    }

    /**
     * Display help to the command.
     */
    @Override
    public void help() {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(WIDTH);
        help.printHelp(ElytronToolMessages.msg.cmdHelp(getToolCommand(), CREDENTIAL_STORE_COMMAND),
                ElytronToolMessages.msg.cmdLineCredentialStoreHelpHeader().concat(ElytronToolMessages.msg.cmdLineActionsHelpHeader()),
                options,
                "",
                true);
    }

    static Map<String, String> parseCredentialStoreProperties(final String attributeString) {
        HashMap<String, String> attributes = new HashMap<>();
        if (attributeString != null) {
            for (String pair : attributeString.split(";")) {
                String[] parts = pair.split("=");
                if (parts[0] != null && !parts[0].isEmpty() && parts[1] != null) {
                    attributes.put(parts[0], parts[1]);
                } else {
                    throw ElytronToolMessages.msg.cannotParseProps();
                }
            }
        }
        return attributes;
    }

    static String formatPropertiesForCli(Map<String, String> properties) {
        if (properties != null && !properties.isEmpty()) {
            properties.remove("create");
            properties.remove("location");
            properties.remove("modifiable");
            boolean first = true;
            StringBuilder attr = new StringBuilder("implementation-properties={");
            for(String name: properties.keySet()) {
                if (!first) {
                    attr.append(",");
                } else {
                    first = false;
                }
                attr.append("\"" + name + "\"=>\"" + properties.get(name) + "\"");
            }
            attr.append("}");
            return attr.toString();
        }
        return "";
    }

    private int getArgumentAsInt(String argument) throws Exception {
        return getArgumentAsInt(argument, -1);
    }

    private int getArgumentAsInt(String argument, int defaultValue) throws Exception {
        if (argument != null && !argument.isEmpty()) {
            try {
                return Integer.parseInt(argument);
            } catch (NumberFormatException e) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw new Exception(e);
            }
        }
        return defaultValue;
    }

    static void getCreateDefaultSummary(Map<String, String> implProps, StringBuilder com, String password) {
        com.append("/subsystem=elytron/credential-store=test:add(");
        com.append("relative-to=jboss.server.data.dir,");
        if (implProps != null && !implProps.isEmpty()) {
            if (implProps.get("create") != null) {
                com.append("create=")
                        .append(implProps.get("create"))
                        .append(",");
            }
            if (implProps.get("modifiable") != null) {
                com.append("modifiable=")
                        .append(implProps.get("modifiable"))
                        .append(",");
            }
            if (implProps.get("location") != null) {
                com.append("location=\"")
                        .append(implProps.get("location"))
                        .append("\",");
            }
            String props = formatPropertiesForCli(implProps);
            if (!props.isEmpty()) {
                com.append(props);
                com.append(",");
            }
        }
        com.append("credential-reference={");
        com.append("clear-text=\"");
        com.append(password);
        com.append("\"})");
    }

    static void getCreatePropertiesCredentialStoreSummary(StringBuilder com, String location) {
        com.append("/subsystem=elytron/secret-key-credential-store=test:add(");
        com.append("relative-to=jboss.server.data.dir,");
        com.append("path=\"").append(location).append("\")");
    }

    static void getUseExpressionExample(StringBuilder com, String cipherTextToken) {
        com.append("/subsystem=example:write-attribute(");
        com.append("name=example,");
        com.append("value=\"${ENC::RESOLVER:").append(cipherTextToken).append("}\")");
    }

    private static void safeClose(Closeable c) {
        if (c != null) try {
            c.close();
        } catch (Throwable ignored) {}
    }
}
