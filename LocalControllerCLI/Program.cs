/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of LocalController <https://github.com/OpenChargingCloud/LocalController>
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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.LocalController.CommandLine;
using cloud.charging.open.LocalController.Configuration;
using cloud.charging.open.LocalController.Logging;

using LC = cloud.charging.open.LocalController.LocalController;

#endregion

namespace cloud.charging.open.LocalController.CLI
{

    /// <summary>
    /// One local controller, with its web interface and a prompt, until 'quit'
    /// or Ctrl+C.
    /// </summary>
    public class Program
    {

        #region (private static) TryTakeValue(Arguments, ref Index, out Value)

        private static Boolean TryTakeValue(String[]     Arguments,
                                            ref Int32    Index,
                                            out String?  Value)
        {

            if (Index + 1 < Arguments.Length && !Arguments[Index + 1].StartsWith("--"))
            {
                Value = Arguments[++Index];
                return true;
            }

            Value = null;
            return false;

        }

        #endregion

        #region (private static) RepositoryRoot()

        /// <summary>
        /// The directory holding LocalControllerCLI.slnx, looked up from the
        /// binary and from the current directory; the current directory when
        /// neither leads to it.
        /// </summary>
        /// <remarks>
        /// The accounts and the configuration default to a place below it, so
        /// that they do not end up in bin/ - where the next "dotnet clean"
        /// would take this controller's accounts with it.
        /// </remarks>
        private static String RepositoryRoot()
        {

            foreach (var start in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
            {

                var directory = new DirectoryInfo(start);

                while (directory is not null)
                {

                    if (File.Exists(Path.Combine(directory.FullName, "LocalControllerCLI.slnx")))
                        return directory.FullName;

                    directory = directory.Parent;

                }

            }

            return Environment.CurrentDirectory;

        }

        #endregion

        #region (private static) PrintUsage()

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: LocalControllerCLI [--port <number>] [--any] [--frontend <dist directory>]");
            Console.WriteLine("                          [--accounts <dir>] [--config <file>]");
            Console.WriteLine("                          [--verbose | --quiet] [--no-trace]");
            Console.WriteLine("                          [--log-file <dir>] [--no-log-file]");
            Console.WriteLine();
            Console.WriteLine("Web interface:");
            Console.WriteLine($"  --port <number>   TCP port to listen on (default: {LC.DefaultHTTPPort})");
            Console.WriteLine("  --any             listen on all addresses instead of 127.0.0.1");
            Console.WriteLine("  --frontend <dir>  serve the web interface from a directory on disk instead of the");
            Console.WriteLine("                    bundle embedded in the assembly - use it together with");
            Console.WriteLine("                    'npm run watch' in libs/LocalController/LocalController/Frontend");
            Console.WriteLine();
            Console.WriteLine("Accounts:");
            Console.WriteLine($"  --accounts <dir>    where the accounts live (default: {LC.DefaultAccountsPath}/ below the");
            Console.WriteLine("                      repository root). Without it a password is made up at the");
            Console.WriteLine($"                      first start for the user '{LC.DefaultAdminUser}' and shown once.");
            Console.WriteLine();
            Console.WriteLine("Configuration:");
            Console.WriteLine($"  --config <file>   where the name servers, the time servers, the OCPP identification");
            Console.WriteLine($"                    and the charging station server of this controller live (default:");
            Console.WriteLine($"                    {ControllerConfigFile.DefaultFileName} below the repository root). Without the");
            Console.WriteLine("                    file the controller runs on the system defaults; the");
            Console.WriteLine("                    Configuration pages of the web interface write it, and every");
            Console.WriteLine("                    change there takes effect at once.");
            Console.WriteLine();
            Console.WriteLine("Log:");
            Console.WriteLine("  -v, --verbose     write every entry to the console, down to the debug ones");
            Console.WriteLine("  -q, --quiet       write only warnings and worse");
            Console.WriteLine("      --no-trace    do not pick up what the libraries below write with DebugX");
            Console.WriteLine($"  --log-file <dir>  where the log files go (default: {LC.DefaultLogPath}/ below the repository");
            Console.WriteLine("                    root): one file per UTC day, every entry down to the debug");
            Console.WriteLine("                    ones, and nothing is ever deleted.");
            Console.WriteLine("      --no-log-file do not write one. Then what the console did not show, and");
            Console.WriteLine($"                    what falls out of the web interface's last {EventLog.DefaultCapacity} entries, is");
            Console.WriteLine("                    gone.");
            Console.WriteLine();
            Console.WriteLine("Whatever the console shows, the web interface shows the whole log under 'Logs'.");
            Console.WriteLine();
            Console.WriteLine("Once it is up, the console is a prompt: 'help' lists what can be typed there,");
            Console.WriteLine("Tab completes it, and 'quit' or Ctrl+C stops the controller. Started where there");
            Console.WriteLine("is no terminal - from a script, under a service manager, in CI, or with the output");
            Console.WriteLine("going into a file - there is no prompt and it simply runs.");
        }

        #endregion


        public static async Task<Int32> Main(String[] Arguments)
        {

            Console.OutputEncoding = System.Text.Encoding.UTF8;

            #region Arguments

            IPPort?  port           = null;
            var      anyAddress     = false;
            String?  frontendDir    = null;
            String?  accountsPath   = null;
            String?  configFilePath = null;
            var      verbose        = false;
            var      quiet          = false;
            var      noTrace        = false;
            String?  logPath        = null;
            var      noLogFile      = false;

            for (var i = 0; i < Arguments.Length; i++)
            {
                switch (Arguments[i])
                {

                    case "--port":
                        if (i + 1 < Arguments.Length && UInt16.TryParse(Arguments[i + 1], out var parsedPort))
                        {
                            port = IPPort.Parse(parsedPort);
                            i++;
                        }
                        else
                        {
                            Console.Error.WriteLine("Missing or invalid port number after --port!");
                            return 2;
                        }
                        break;

                    case "--any":
                        anyAddress = true;
                        break;

                    case "--frontend":
                        if (!TryTakeValue(Arguments, ref i, out frontendDir))
                        {
                            Console.Error.WriteLine("Missing directory after --frontend!");
                            return 2;
                        }
                        break;

                    case "--accounts":
                        if (!TryTakeValue(Arguments, ref i, out accountsPath))
                        {
                            Console.Error.WriteLine("Missing directory after --accounts!");
                            return 2;
                        }
                        break;

                    case "--config":
                        if (!TryTakeValue(Arguments, ref i, out configFilePath))
                        {
                            Console.Error.WriteLine("Missing file after --config!");
                            return 2;
                        }
                        break;

                    case "-v":
                    case "--verbose":
                        verbose = true;
                        break;

                    case "-q":
                    case "--quiet":
                        quiet = true;
                        break;

                    case "--no-trace":
                        noTrace = true;
                        break;

                    case "--log-file":
                        if (!TryTakeValue(Arguments, ref i, out logPath))
                        {
                            Console.Error.WriteLine("Missing directory after --log-file!");
                            return 2;
                        }
                        break;

                    case "--no-log-file":
                        noLogFile = true;
                        break;

                    case "-h":
                    case "--help":
                        PrintUsage();
                        return 0;

                    default:
                        Console.Error.WriteLine($"Unknown argument '{Arguments[i]}'!");
                        PrintUsage();
                        return 2;

                }
            }

            if (verbose && quiet)
            {
                Console.Error.WriteLine("--verbose and --quiet ask for opposite things!");
                return 2;
            }

            #endregion

            #region Where the web interface comes from

            // A directory given on the command line wins, so that
            // "npm run watch" beside a running controller shows up in the
            // browser on a reload, without rebuilding the C# side.
            IStaticContentSource? frontend = null;

            if (frontendDir is not null)
            {

                if (!Directory.Exists(frontendDir))
                {
                    Console.Error.WriteLine($"The frontend directory '{frontendDir}' does not exist!");
                    return 2;
                }

                frontend = new FileSystemContentSource(frontendDir);

            }

            #endregion

            #region The local controller

            LC localController;

            try
            {
                localController = new LC(

                                      HTTPHostname:     anyAddress
                                                            ? IPvXAddress.Any
                                                            : IPv4Address.Localhost,

                                      HTTPPort:         port,

                                      AccountsPath:     accountsPath ?? Path.Combine(RepositoryRoot(), LC.DefaultAccountsPath),

                                      ConfigFile:       new ControllerConfigFile(
                                                            configFilePath ?? Path.Combine(RepositoryRoot(), ControllerConfigFile.DefaultFileName)
                                                        ),

                                      Frontend:         frontend,

                                      ConsoleLogLevel:  verbose ? LogLevel.Debug
                                                            : quiet ? LogLevel.Warning
                                                            : LogLevel.Info,

                                      // On unless it is switched off. A console nobody
                                      // was watching kept nothing, and the log a
                                      // browser shows goes with the process - so the
                                      // one place a question about last night can still
                                      // be answered from is a file.
                                      LogPath:          noLogFile
                                                            ? null
                                                            : logPath ?? Path.Combine(RepositoryRoot(), LC.DefaultLogPath),

                                      BridgeDebugLog:   !noTrace

                                  );
            }
            catch (Exception e)
            {

                Console.Error.WriteLine($"The local controller could not be set up: {e.Message}");

                // A controller that does not come up at all is the one moment
                // the stack trace is worth more than a tidy console.
                if (verbose)
                    Console.Error.WriteLine(e);

                return 1;

            }

            await using (localController)
            {

                await localController.Start();

                #region What somebody who just started this needs to know

                Console.WriteLine();
                Console.WriteLine($"  web interface  {localController.WebInterfaceURL}");
                Console.WriteLine($"  JSON API       {localController.WebInterfaceURL}api/v1/status");
                Console.WriteLine($"  event stream   {localController.WebInterfaceURL}api/v1/events");
                Console.WriteLine($"  frontend from  {localController.Frontend.Description}");

                var builtFrom = BuiltFrom.Repositories.ToArray();

                if (builtFrom.Length > 0)
                {

                    // One line each, and the whole hash. This is meant to be read
                    // out of a bug report and pasted into a checkout, and an
                    // abbreviation is a thing somebody then has to guess the rest
                    // of. The column is as wide as the longest name rather than a
                    // number picked today, so a repository joining later still
                    // lines up.
                    var width = builtFrom.Max(repository => repository.Repository!.Length);

                    for (var i = 0; i < builtFrom.Length; i++)
                        Console.WriteLine((i == 0 ? "  built from     " : "                 ") +
                                          builtFrom[i].Repository!.PadRight(width) +
                                          "  " +
                                          builtFrom[i].Commit);

                }

                Console.WriteLine($"  accounts       {localController.ExtAPI.Users.Count()} user(s) in {localController.AccountsPath}");
                Console.WriteLine($"  sign in at     {localController.WebInterfaceURL}{LC.ExtAPIPath.ToString().Trim('/')}/login");
                Console.WriteLine($"  configuration  {localController.ConfigFile.Path}");
                Console.WriteLine($"  log files      {localController.LogPath ?? "none (--no-log-file)"}");
                Console.WriteLine($"  OCPP node      {localController.Node.Id} ({localController.Node.VendorName} {localController.Node.Model})");
                Console.WriteLine($"  stations       {(localController.OCPPServerEnabled
                                                              ? $"{localController.OCPPServerURL}{(localController.OCPPServerTLS ? "" : " (unencrypted)")}, " +
                                                                $"{localController.StationLogins.EnabledCount} login(s)"
                                                              : "switched off - no charging station can connect")}");
                Console.WriteLine($"  name servers   {(localController.DNSEnabled ? String.Join(", ", localController.DNSClient.DNSServers) : "switched off")}");
                #region The time servers

                var bands = localController.TimeSources.Bands();
                var asked = bands.SelectMany(band => band).ToArray();

                // Without the root's dot, which a domain name prints itself
                // with: four names in a row, each ending in a dot, read as four
                // typing mistakes. What goes back into the file keeps it.
                //
                // And the one server the group asks rather than the single
                // client's: a list of one in the file leaves that client where
                // it was.
                if (asked.Length <= 1)
                    Console.WriteLine($"  time server    {(asked.Length == 1 ? asked[0].Hostname : localController.NTSClient.Hostname).Trimmed}" +
                                      (localController.NTSEnabled ? "" : " (switched off)"));

                else
                {

                    // One line per band, because a band is the unit that is
                    // asked at once - putting two bands on one line would read
                    // as six equal servers when it is two and then four.
                    for (var i = 0; i < bands.Count; i++)
                        Console.WriteLine((i == 0 ? "  time servers   " : "                 ") +
                                          String.Join(", ", bands[i].Select(source => source.Hostname.Trimmed)) +
                                          (bands.Count > 1 ? $"   (priority {bands[i][0].Priority})" : ""));

                    Console.WriteLine($"                 at least {localController.TimeSources.MinServers} of them must answer" +
                                      (localController.NTSEnabled ? "" : " - and NTS is switched off"));

                }

                #endregion

                if (localController.GeneratedPassword is not null)
                {
                    Console.WriteLine();
                    Console.WriteLine("  ┌─ First start: there were no accounts, so one was made up for you ─────────");
                    Console.WriteLine($"  │  user      {LC.DefaultAdminUser}");
                    Console.WriteLine($"  │  password  {localController.GeneratedPassword}");
                    // Named rather than called "a hash", and read from the
                    // implementation rather than typed here, so the box cannot
                    // end up describing a scheme this controller no longer uses.
                    // "i=600000" is also how the accounts file writes it down,
                    // which is where somebody checking this will look.
                    Console.WriteLine($"  │  It is shown here once and kept only as a {SecurePassword.PBKDF2SHA256} hash");
                    Console.WriteLine($"  │  over {SecurePassword.DefaultIterations} iterations. Write it down.");
                    Console.WriteLine("  └───────────────────────────────────────────────────────────────────────────");
                }

                Console.WriteLine();

                #endregion

                #region The command line, until 'quit' or Ctrl+C

                // Whether anybody can type here at all. Started from a script,
                // from a service manager or in CI, this process has no terminal
                // on its input and Console.ReadKey throws rather than waiting -
                // and there would be nobody to type anyway. Then the controller
                // simply runs, exactly as it did before there was a command
                // line, and the web interface is how it is spoken to.
                //
                // The output counts too: the prompt is drawn by moving the
                // cursor, and with the output going into "| tee" or a file there
                // is no cursor to move. Measured on Windows with the vehicle,
                // whose prompt then looked at its input only: the prompt threw
                // while drawing itself, before a key was pressed, and the
                // program was gone within 200 ms of its banner - with exit code
                // 0, a program that said all was well.
                var canBeTypedAt = !Console.IsInputRedirected &&
                                   !Console.IsOutputRedirected;

                Console.WriteLine(canBeTypedAt
                                      ? "Type 'help' for what can be typed here, 'quit' or Ctrl+C to stop."
                                      : "Press Ctrl+C to stop. (No terminal here, so nothing to type at.)");
                Console.WriteLine();

                var stopped = new TaskCompletionSource();

                // Ctrl+C still means stop, as it always has here. The command
                // line adds a handler of its own for it, which cancels whatever
                // command is running; both fire, and that is the intended
                // reading of Ctrl+C - abandon what is running and shut the
                // controller down. 'quit' is the same thing said politely.
                Console.CancelKeyPress += (_, e) => {
                    e.Cancel = true;
                    stopped.TrySetResult();
                };

                if (canBeTypedAt)
                {

                    var cli             = new ControllerCLI(localController);
                    var brokeAtOnce     = false;

                    while (true)
                    {

                        // From here two things write on one screen: this command
                        // line, and the controller's log from whichever thread
                        // did the thing it is reporting. So the log stops writing
                        // of its own accord and asks the command line for the
                        // screen instead - which takes the half-typed command off
                        // it, writes the entry whole, and puts the command back
                        // with the cursor where it was.
                        localController.ShareConsoleWith(cli.WriteBlock);

                        // On a thread of its own, because Console.ReadKey blocks
                        // the one it is called on: awaited directly, the command
                        // line would keep this thread inside ReadKey and Ctrl+C
                        // would have nobody left to wake.
                        var since   = System.Diagnostics.Stopwatch.GetTimestamp();
                        var typing  = Task.Run(cli.Run);

                        await Task.WhenAny(stopped.Task, typing);

                        if (!typing.IsFaulted)
                            break;

                        // A command line that broke is not somebody asking for
                        // the controller to stop. What broke it first, in the
                        // vehicle and the charging station, was a line typed
                        // wider than the window: until Styx learned to show such
                        // a line through a window onto it, it threw out of the
                        // line editor - measured in 80 columns, "Parameter
                        // 'left', actual value was 80" - and a program that took
                        // that for 'quit' shut down with exit code 0. That cause
                        // is gone; this is for the next one.
                        //
                        // The console goes back to the log first, with a lock
                        // of its own, because the command line's way of writing
                        // may be what broke: a prompt that fails while drawing
                        // itself stays registered as the line on the screen,
                        // and every entry after that fails trying to take it
                        // off again.
                        //
                        // Then a new prompt - unless the last one was already
                        // a new one and broke again the moment it started.
                        // That is a console a prompt cannot be drawn on at all,
                        // and asking a third time would only fail a third time.
                        // How fast the first one broke says nothing: a line
                        // pasted in straight after the start is still a line.
                        var padlock = new Lock();

                        localController.ShareConsoleWith(write => { lock (padlock) { write(); } });

                        var atOnce = System.Diagnostics.Stopwatch.GetElapsedTime(since) < TimeSpan.FromSeconds(1);
                        var giveUp = atOnce && brokeAtOnce;

                        brokeAtOnce = atOnce;

                        // On one line, as every entry is: the message of an
                        // exception may carry line breaks of its own, and a
                        // second line of an entry has no time, no level and no
                        // tags.
                        var why = typing.Exception?.GetBaseException().Message.ReplaceLineEndings(" ");

                        localController.Log.Warning(
                            $"The command line stopped working: {why} " +
                            (giveUp
                                 ? "A new one broke again as soon as it started, so there is none; the local controller keeps running, and Ctrl+C stops it."
                                 : "A new one is started."),
                            "cli"
                        );

                        if (giveUp)
                        {
                            await stopped.Task;
                            break;
                        }

                    }

                }

                else
                    await stopped.Task;

                #endregion

            }

            #endregion

            return 0;

        }

    }

}
