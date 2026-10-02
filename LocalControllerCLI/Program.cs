/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of LocalControllerCLI <https://github.com/OpenChargingCloud/LocalControllerCLI>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.LocalController.CommandLine;

using LC = cloud.charging.open.LocalController.LocalController;

#endregion

namespace cloud.charging.open.LocalController.CLI
{

    /// <summary>
    /// One local controller, with its web interface and a prompt, until 'quit',
    /// Ctrl+C or SIGTERM.
    /// </summary>
    /// <remarks>
    /// What every kind of node's program does is the node's: the switches and
    /// the words -h explains them with, why it could not be set up or could not
    /// start, what goes into the certificate store, the banner and the prompt.
    /// What is left here is the local controller's: what its configuration
    /// holds, its charging station server's port, and what its banner says of
    /// OCPP.
    /// </remarks>
    public class Program
    {

        #region (private static) Usage

        /// <summary>
        /// What -h shows: every node's switches, in a local controller's words.
        /// </summary>
        private static readonly NodeUsage Usage = new (

            Program:            "LocalControllerCLI",
            Kind:               LC.LocalControllerKind,
            DefaultPort:        LC.DefaultHTTPPort,
            FrontendSources:    "libs/LocalController/LocalController/Frontend",

            ConfigurationSays:  "where the name servers, the time servers, the OCPP identification and the charging station " +
                               $"server of this controller live (default: {WWCPConfigFile.DefaultFileName} below the repository " +
                                "root). Without the file the controller runs on the system defaults; the Configuration pages " +
                                "of the web interface write it, and every change there takes effect at once.",

            CertificateKinds:   LC.CertificateKinds

        );

        #endregion

        #region (private static) WhatToDoAbout(Problem)

        /// <summary>
        /// What somebody can do about the charging station server's port, which
        /// is set in the configuration file rather than with --port; null for
        /// the web interface's, which is every node's.
        /// </summary>
        private static String? WhatToDoAbout(PortUnavailableException Problem)

            => Problem.Whose == LC.StationServerPort

                   ? "Another copy of this controller already running is the usual answer. Stop it, or give the " +
                     "charging station server another port: \"port\" in the \"ocppServer\" section of the configuration file."

                   : null;

        #endregion


        public static async Task<Int32> Main(String[] Arguments)
        {

            Console.OutputEncoding = System.Text.Encoding.UTF8;

            #region Arguments

            // Every node's switches; a local controller has none of its own.
            var arguments = NodeArguments.Parse(Arguments);

            if (arguments.Refused(Usage) is Int32 refused)
                return refused;

            if (arguments.RefuseTheRest(Usage) is Int32 unknown)
                return unknown;

            var root = NodeProgram.RepositoryRoot("LocalControllerCLI.slnx");

            #endregion

            #region The local controller

            LC localController;

            try
            {
                localController = new LC(
                                      HTTPHostname:      arguments.HTTPHostname,
                                      HTTPPort:          arguments.Port,
                                      AccountsPath:      arguments.AccountsPathBelow(root),
                                      ConfigFile:        new WWCPConfigFile(arguments.ConfigFilePathBelow(root)),
                                      Frontend:          arguments.Frontend,
                                      CertificatesPath:  arguments.CertificatesPath,
                                      ConsoleLogLevel:   arguments.ConsoleLogLevel,
                                      LogPath:           arguments.LogPathBelow(root),
                                      BridgeDebugLog:    !arguments.NoTrace,
                                      SSH:               arguments.SSH
                                  );
            }
            catch (Exception e)
            {
                return NodeProgram.CouldNotBeSetUp(LC.LocalControllerKind, e, arguments.Verbose);
            }

            await using (localController)
            {

                // What somebody signed in over SSH gets: this program's own command
                // line, with its commands beside the node's.
                localController.CommandLines = (terminal, caller) => new ControllerCLI(localController, terminal, caller);

                if (localController.ImportCertificates(arguments, out _) is Int32 notImported)
                    return notImported;

                if (arguments.ListCertificates)
                    localController.ListCertificates();

                if (await localController.Started(arguments.Verbose, WhatToDoAbout) is Int32 notStarted)
                    return notStarted;

                #region What somebody who just started this needs to know

                foreach (var line in localController.Banner(
                                         OfTheKind: [
                                             ("OCPP node",  $"{localController.Node.Id} ({localController.Node.VendorName} {localController.Node.Model})"),
                                             ("stations",   localController.OCPPServerEnabled
                                                                ? $"{localController.OCPPServerURL}{(localController.OCPPServerTLS ? "" : " (unencrypted)")}, " +
                                                                  $"{localController.StationLogins.EnabledCount} login(s)"
                                                                : "switched off - no charging station can connect")
                                         ]))
                    Console.WriteLine(line);

                #endregion

                #region The command line, until 'quit', Ctrl+C or SIGTERM

                // The node's: a prompt where somebody can type, and waiting
                // where nobody can, with the log sharing the screen.
                await new ControllerCLI(localController).RunUntilStopped();

                #endregion

            }

            #endregion

            return 0;

        }

    }

}
