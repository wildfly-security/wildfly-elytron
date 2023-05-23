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

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

import static org.wildfly.security.tool.Params.DEBUG_PARAM;
import static org.wildfly.security.tool.Params.HELP_PARAM;
import static org.wildfly.security.tool.Params.ITERATION_PARAM;
import static org.wildfly.security.tool.Params.SALT_PARAM;
import static org.wildfly.security.util.PasswordUtil.generateSecureRandomString;

/**
 * Mask Command
 *
 * This command is used for creation of masked password strings.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
class MaskCommand extends Command {

    /**
     * Command string
     */
    public static final String MASK_COMMAND = "mask";
    static final String SECRET_PARAM = "secret";

    private final int defaultIterationCount = 10000;

    private final Options options;
    private CommandLineParser parser = new DefaultParser();
    private CommandLine cmdLine = null;

    MaskCommand() {
        Option salt = new Option("s", SALT_PARAM, true, ElytronToolMessages.msg.cmdMaskSaltDesc());
        Option iteration = new Option("i", ITERATION_PARAM, true, ElytronToolMessages.msg.cmdMaskIterationCountDesc());
        Option h = new Option("h", HELP_PARAM, false, ElytronToolMessages.msg.cmdLineHelp());
        Option x = new Option("x", SECRET_PARAM, true, ElytronToolMessages.msg.cmdMaskSecretDesc());
        Option d = new Option("d", DEBUG_PARAM, false, ElytronToolMessages.msg.cmdLineDebug());
        x.setArgName("to encrypt");
        options = new Options();
        options.addOption(x);
        options.addOption(h);
        options.addOption(salt);
        options.addOption(iteration);
        options.addOption(d);
    }

    @Override
    public void execute(String[] args) throws Exception {
        if (new SecureRandom().getProvider().getName().toLowerCase().contains("fips")) {
            System.out.println(ElytronToolMessages.msg.fipsModeNotAllowed());
            return;
        }
        setStatus(GENERAL_CONFIGURATION_ERROR);
        cmdLine = parser.parse(options, args, false);
        setEnableDebug(cmdLine.hasOption(DEBUG_PARAM));
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            return;
        }

        printDuplicatesWarning(cmdLine);

        String salt = cmdLine.getOptionValue(SALT_PARAM);
        if (salt == null) {
            salt = generateSecureRandomString(8);
            System.out.println(ElytronToolMessages.msg.invalidParameterGeneratedWillBeUsed(SALT_PARAM, salt));
        }
        String sIteration = cmdLine.getOptionValue(ITERATION_PARAM);
        int iterationCount = -1;
        if (sIteration != null && !sIteration.isEmpty()) {
            try {
                iterationCount = Integer.parseInt(sIteration);
                if (iterationCount < 1) {
                    System.out.println(ElytronToolMessages.msg.invalidParameterMustBeIntBetween(ITERATION_PARAM, 1, Integer.MAX_VALUE));
                }
            } catch (NumberFormatException e) {
                System.out.println(ElytronToolMessages.msg.invalidParameterMustBeIntBetween(ITERATION_PARAM, 1, Integer.MAX_VALUE));
            }
        }
        if (iterationCount < 1) {
            System.out.println(ElytronToolMessages.msg.invalidParameterDefaultWillBeUsed(ITERATION_PARAM, Integer.toString(defaultIterationCount)));
            iterationCount = defaultIterationCount;
        }

        String secret = cmdLine.getOptionValue(SECRET_PARAM);
        if (secret == null) {
            secret = prompt(false, ElytronToolMessages.msg.maskSecretPrompt(), true, ElytronToolMessages.msg.maskSecretPromptConfirm());
            if (secret == null) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw ElytronToolMessages.msg.secretNotSpecified();
            }
        }

        final String masked = computeMasked(secret, salt, iterationCount);
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
        System.out.println(masked);
    }

    static String computeMasked(String secret, String salt, int iteration) throws GeneralSecurityException {
        PasswordBasedEncryptionUtil encryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .picketBoxCompatibility()
                .salt(salt)
                .iteration(iteration)
                .encryptMode()
                .build();
        return "MASK-" + encryptUtil.encryptAndEncode(secret.toCharArray()) + ";" + salt + ";" + String.valueOf(iteration);
    }

    static char[] decryptMasked(String maskedPassword) throws GeneralSecurityException {
        int maskLength = "MASK-".length();
        if (maskedPassword == null || maskedPassword.length() <= maskLength) {
            throw ElytronToolMessages.msg.wrongMaskedPasswordFormat();
        }
        String[] parsed = maskedPassword.substring(maskLength).split(";");
        if (parsed.length != 3) {
            throw ElytronToolMessages.msg.wrongMaskedPasswordFormat();
        }
        String encoded = parsed[0];
        String salt = parsed[1];
        int iteration = Integer.parseInt(parsed[2]);
        PasswordBasedEncryptionUtil encryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .picketBoxCompatibility()
                .salt(salt)
                .iteration(iteration)
                .decryptMode()
                .build();
        return encryptUtil.decodeAndDecrypt(encoded);
    }

    /**
     * Display help to the command.
     */
    @Override
    public void help() {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(WIDTH);
        help.printHelp(ElytronToolMessages.msg.cmdHelp(getToolCommand(), MASK_COMMAND),
                ElytronToolMessages.msg.cmdMaskHelpHeader().concat(ElytronToolMessages.msg.cmdLineActionsHelpHeader()),
                options,
                "",
                true);
    }
}
