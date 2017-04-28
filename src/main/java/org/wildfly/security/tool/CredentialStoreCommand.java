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

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Credential Store Command
 * Performs credential store related operations.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
class CredentialStoreCommand extends Command {

    public static int ACTION_NOT_DEFINED = 5;
    public static int ALIAS_NOT_FOUND = 6;
    public static int GENERAL_CONFIGURATION_ERROR = 7;

    public static final String CREDENTIAL_STORE_COMMAND = "credential-store";

    public static final String STORE_LOCATION_PARAM = "location";
    public static final String IMPLEMENTATION_PROPERTIES_PARAM = "properties";
    public static final String CREDENTIAL_STORE_PASSWORD_PARAM = "password";
    public static final String CREDENTIAL_STORE_TYPE_PARAM = "type";
    public static final String SALT_PARAM = "salt";
    public static final String ITERATION_PARAM = "iteration";
    public static final String PASSWORD_CREDENTIAL_VALUE_PARAM = "secret";
    public static final String ADD_ALIAS_PARAM = "add";
    public static final String CHECK_ALIAS_PARAM = "exists";
    public static final String ALIASES_PARAM = "aliases";
    public static final String REMOVE_ALIAS_PARAM = "remove";
    public static final String CREATE_CREDENTIAL_STORE_PARAM = "create";
    public static final String HELP_PARAM = "help";
    public static final String PRINT_SUMMARY_PARAM = "summary";
    public static final String ENTRY_TYPE_PARAM = "entry-type";
    public static final String OTHER_PROVIDERS_PARAM = "other-providers";

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
        opt = new Option("p", CREDENTIAL_STORE_PASSWORD_PARAM, true, ElytronToolMessages.msg.cmdLineCredentialStorePassword());
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
        options.addOption("c", CREATE_CREDENTIAL_STORE_PARAM, false, ElytronToolMessages.msg.cmdLineCreateCredentialStoreDesc());
        opt = new Option("t", CREDENTIAL_STORE_TYPE_PARAM, true, ElytronToolMessages.msg.cmdLineCredentialStoreTypeDesc());
        opt.setArgName("type");
        options.addOption(opt);
        options.addOption("f", PRINT_SUMMARY_PARAM, false, ElytronToolMessages.msg.cmdLinePrintSummary());

        OptionGroup og = new OptionGroup();
        Option a = new Option("a", ADD_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineAddAliasDesc());
        a.setArgName("alias");
        Option e = new Option("e", CHECK_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineCheckAliasDesc());
        e.setArgName("alias");
        Option r = new Option("r", REMOVE_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineRemoveAliasDesc());
        r.setArgName("alias");
        Option v = new Option("v", ALIASES_PARAM, false, ElytronToolMessages.msg.cmdLineAliasesDesc());
        Option h = new Option("h", HELP_PARAM, false, ElytronToolMessages.msg.cmdLineHelp());
        og.addOption(a);
        og.addOption(e);
        og.addOption(r);
        og.addOption(v);
        options.addOptionGroup(og);
        options.addOption(h);
    }

    @Override
    public void execute(String[] args) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        cmdLine = parser.parse(options, args, false);
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            return;
        }

        printDuplicatesWarning(cmdLine);

        String location = cmdLine.getOptionValue(STORE_LOCATION_PARAM);
        String csPassword = cmdLine.getOptionValue(CREDENTIAL_STORE_PASSWORD_PARAM);
        String salt = cmdLine.getOptionValue(SALT_PARAM);
        String csType = cmdLine.getOptionValue(CREDENTIAL_STORE_TYPE_PARAM, KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
        int iterationCount = getArgumentAsInt(cmdLine.getOptionValue(ITERATION_PARAM));
        String entryType = cmdLine.getOptionValue(ENTRY_TYPE_PARAM);
        String otherProviders = cmdLine.getOptionValue(OTHER_PROVIDERS_PARAM);
        boolean createStorage = cmdLine.hasOption(CREATE_CREDENTIAL_STORE_PARAM);
        boolean printSummary = cmdLine.hasOption(PRINT_SUMMARY_PARAM);
        String secret = cmdLine.getOptionValue(PASSWORD_CREDENTIAL_VALUE_PARAM);

        Map<String, String> implProps = parseCredentialStoreProperties(cmdLine.getOptionValue(IMPLEMENTATION_PROPERTIES_PARAM));

        CredentialStore credentialStore = CredentialStore.getInstance(csType);
        implProps.put("location", location);
        implProps.putIfAbsent("modifiable", Boolean.TRUE.toString());
        implProps.putIfAbsent("create", Boolean.valueOf(createStorage).toString());
        implProps.putIfAbsent("keyStoreType", "JCEKS");

        CredentialStore.CredentialSourceProtectionParameter credentialSourceProtectionParameter = null;
        if (csPassword == null) {
            // prompt for password
            csPassword = prompt(false, ElytronToolMessages.msg.credentialStorePasswordPrompt(), true, ElytronToolMessages.msg.credentialStorePasswordPromptConfirm());
        }
        if (csPassword != null) {
            credentialSourceProtectionParameter = new CredentialStore.CredentialSourceProtectionParameter(
                            IdentityCredentials.NONE.withCredential(
                                    new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, csPassword.toCharArray()))));
        }
        credentialStore.initialize(implProps,
                credentialSourceProtectionParameter,
                getProviders(otherProviders));
        if (cmdLine.hasOption(ADD_ALIAS_PARAM)) {
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
            credentialStore.store(alias, createCredential(secret, entryType));
            credentialStore.flush();
            System.out.println(ElytronToolMessages.msg.aliasStored(alias));
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else if (cmdLine.hasOption(REMOVE_ALIAS_PARAM)) {
            String alias = cmdLine.getOptionValue(REMOVE_ALIAS_PARAM);
            if (credentialStore.exists(alias, entryTypeToCredential(entryType))) {
                credentialStore.remove(alias, entryTypeToCredential(entryType));
                credentialStore.flush();
                System.out.println(ElytronToolMessages.msg.aliasRemoved(alias));
                setStatus(ElytronTool.ElytronToolExitStatus_OK);
            } else {
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
                setStatus(ALIAS_NOT_FOUND);
            }

        } else if (cmdLine.hasOption(CHECK_ALIAS_PARAM)) {
            String alias = cmdLine.getOptionValue(CHECK_ALIAS_PARAM);
            if (credentialStore.exists(alias, entryTypeToCredential(entryType))) {
                setStatus(ElytronTool.ElytronToolExitStatus_OK);
                System.out.println(ElytronToolMessages.msg.aliasExists(alias));
            } else {
                setStatus(ALIAS_NOT_FOUND);
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
            }
        } else if (cmdLine.hasOption(ALIASES_PARAM)) {
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
        } else if (cmdLine.hasOption(CREATE_CREDENTIAL_STORE_PARAM)) {
            //this must be always the last available option.
            credentialStore.flush();
            System.out.println(ElytronToolMessages.msg.credentialStoreCreated());
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else {
            setStatus(ACTION_NOT_DEFINED);
            throw ElytronToolMessages.msg.actionToPerformNotDefined();
        }


        if (printSummary) {

            StringBuilder com = new StringBuilder();
            String password = csPassword == null ? "" : csPassword;

            if (cmdLine.hasOption(ADD_ALIAS_PARAM)) {
                if (csPassword != null && !csPassword.startsWith("MASK-") && salt != null && iterationCount > -1) {
                    password = MaskCommand.computeMasked(csPassword, salt, iterationCount);
                }

                if (createStorage) {
                    getCreateSummary(location, implProps, com, password);
                    com.append("\n");
                }

                com.append("/subsystem=elytron/credential-store=test/alias=");
                com.append(cmdLine.getOptionValue(ADD_ALIAS_PARAM));
                com.append(":add(secret-value=\"");
                com.append(secret);
                com.append("\")");

            } else if (cmdLine.hasOption(REMOVE_ALIAS_PARAM)) {

                com.append("/subsystem=elytron/credential-store=test/alias=");
                com.append(cmdLine.getOptionValue(REMOVE_ALIAS_PARAM));
                com.append(":remove()");

            } else if (cmdLine.hasOption(ALIASES_PARAM)) {
                com.append("/subsystem=elytron/credential-store=test:read-children-names(child-type=alias)");
            } else if (cmdLine.hasOption(CHECK_ALIAS_PARAM)) {
                com.append("ls /subsystem=elytron/credential-store=test1/alias=");
                com.append(cmdLine.getOptionValue(CHECK_ALIAS_PARAM));
            } else if ( cmdLine.hasOption(CREATE_CREDENTIAL_STORE_PARAM) ){
                getCreateSummary(location, implProps, com, password);
            }

            System.out.println(ElytronToolMessages.msg.commandSummary(com.toString()));
        }
    }

    private Credential createCredential(final String secret, String entryType) {
        if (entryType == null || PasswordCredential.class.getName().equals(entryType)) {
            return new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret.toCharArray()));
        } else {
            throw ElytronToolMessages.msg.unknownEntryType(entryType);
        }
    }

    private Class<? extends Credential> entryTypeToCredential(String entryType) {
        if (entryType == null || PasswordCredential.class.getName().equals(entryType)) {
            return PasswordCredential.class;
        } else {
            throw ElytronToolMessages.msg.unknownEntryType(entryType);
        }
    }

    private Provider[] getProviders(String otherProviders) {
        if (otherProviders != null && !otherProviders.isEmpty()) {
            String[] providerNames = otherProviders.split(",");
            Provider[] providers = new Provider[providerNames.length];
            int i = 0;
            for(String p: providerNames) {
                Provider provider = Security.getProvider(p.trim());
                if (provider == null) {
                    throw ElytronToolMessages.msg.unknownProvider(p.trim());
                }
                providers[i++] = provider;
            }
            return providers;
        } else {
            return null;
        }
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
        help.printHelp(ElytronToolMessages.msg.cmdHelp(ElytronTool.TOOL_JAR, CREDENTIAL_STORE_COMMAND),
                ElytronToolMessages.msg.cmdLineCredentialStoreHelpHeader(),
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
        if (properties != null || !properties.isEmpty()) {
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
        if (argument != null && !argument.isEmpty()) {
            try {
                return Integer.parseInt(argument);
            } catch (NumberFormatException e) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw new Exception(e);
            }
        }
        return -1;
    }

    private void getCreateSummary(String location, Map<String, String> implProps, StringBuilder com, String password) {
        com.append("/subsystem=elytron/credential-store=cs:add(");
        com.append("relative-to=jboss.server.data.dir,");
        if (location != null) {
            com.append("location=\"" + location + "\",");
        }
        com.append("create=true,");
        String props = formatPropertiesForCli(implProps);
        if (!props.isEmpty()) {
            com.append(props);
            com.append(",");
        }
        com.append("credential-reference={");
        com.append("clear-text=\"");
        com.append(password);
        com.append("\"})");
    }
}
