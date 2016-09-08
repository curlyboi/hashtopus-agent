using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using System.Diagnostics;
using System.Management;
using System.IO;
using System.Net;
using System.Threading;
using System.IO.Compression;
using System.Globalization;
using System.ComponentModel;
using System.Xml;

namespace hashtopus
{
    static class Chunk
    {
        public static string id = "";
        public static string start = "";
        public static string size = "";
        public static string status = "";
        public static string curKU = "";
        public static string curKUlast = "";
        public static string rProgress = "";
        public static string rSize = "";
        public static string totalSpeed = "";

        public static void Init()
        {
            id = "0";
            start = "0";
            size = "0";
            InitProg();
        }

        public static void InitProg()
        {
            status = "0";
            curKU = "0";
            curKUlast = "0";
            rProgress = "0";
            rSize = "0";
            totalSpeed = "0";
        }

        public static uint Load()
        {
            // load a chunk of task the agent is assigned to
            GlobObj.Out("Requesting chunk...");
            string[] responze = new string[] { };
            try
            {
                string chunkUrl = string.Format("a=chunk&token={0}&task={1}", Token.value, Task.id);
                responze = WebComm.DownloadString(chunkUrl).Split(Htp.separator);
            }
            catch (WebException e)
            {
                WebComm.Error(e);
                return 0;
            }
            string consOut;
            uint retval;
            switch (responze[0])
            {
                case "chunk_ok":
                    id = responze[1];
                    start = responze[2];
                    size = responze[3];
                    consOut = string.Format("received: {0} (S: {1}, L: {2})", id, start, size);
                    retval = 1;
                    break;

                case "chunk_nok":
                    consOut = string.Format("failed: {0}", responze[1]);
                    retval = 0;
                    break;

                case "bench_req":
                    Task.benchTime = responze[1];
                    consOut = string.Format("benchmark required ({0}s)", Task.benchTime);
                    retval = 2;
                    break;

                case "keyspace_req":
                    consOut = "keyspace measuring required";
                    retval = 3;
                    break;

                default:
                    consOut = "Chunk acquisition returned nonsense.";
                    retval = 0;
                    break;
            }
            GlobObj.OutL(consOut);
            return retval;
        }


    }

    static class Hashcat
    {
        public static string dir = "";
        public static string exe = "";
        public static Process hcProcess = null;
        public static uint mode = 0; // 3=keyspace measure, 2=benchmark, 1=crack, 0=none
        public static int exitCode = 0;
        public static bool okExit = false;
        public static double lastRun = 0;

        public static void ClearDir()
        {
            if (Directory.Exists(dir))
            {
                GlobObj.OutL("Clearing directories...");
                Directory.Delete(dir, true);
            }
        }

        public static bool Update()
        {
            dir = Path.Combine(Dirs.install, Subdirs.hashcat);
            exe = Path.Combine(dir, "hashcat" + Htp.cpu + "." + (Htp.os == 1 ? "bin" : "exe"));

            // check if hashcat upgrading is needed and upgrade if yes
            string forceUpdate = "";
            if (!File.Exists(exe))
            {
                // the executable doesn't exist - tell the server we need to update
                // even we might be already marked as running the current version
                forceUpdate = "&force=1";
            }
            string[] responze;
            try
            {
                responze = WebComm.DownloadString("a=down&token=" + Token.value + forceUpdate).Split(Htp.separator);
            }
            catch (WebException e)
            {
                WebComm.Error(e);
                return false;
            }
            switch (responze[0])
            {
                case "down_ok":
                    // there is an update available
                    GlobObj.Out("New Hashcat version available, downloading...");

                    // download installation archive
                    string hcarchive = Path.Combine(Dirs.install, "hashcat.zip");
                    string url = string.Format("a=file&token={0}&file={1}", Token.value, responze[1]);
                    if (File.Exists(hcarchive)) File.Delete(hcarchive);
                    if (!WebComm.DownloadFile(url, hcarchive)) return false;

                    if (new FileInfo(hcarchive).Length == 0)
                    {
                        GlobObj.OutL("Downloaded empty file.");
                        File.Delete(hcarchive);
                        return false;
                    }

                    // cleanup whatever left from last time (should not be any, but just to be sure)
                    ClearDir();

                    // call the extract function
                    GlobObj.Out("Unzipping...");
                    Zip.UnzipFile(hcarchive, Dirs.install);
                    GlobObj.OutL("OK");

                    // delete the archive, it's not needed
                    File.Delete(hcarchive);

                    // check if it worked
                    if (!Directory.Exists(dir))
                    {
                        GlobObj.OutL("Hashcat directory was not unzipped.");
                        return false;
                    }

                    // check if the operation was successful
                    if (!File.Exists(exe))
                    {
                        if (Directory.Exists(dir)) Directory.Delete(dir, true);
                        GlobObj.OutL("Executable for this platform was not delivered.");
                        return false;
                    }
                    else
                    {
                        // chmod the binary on linux
                        if (Htp.os == 1)
                            Process.Start("chmod", "+x \"" + exe + "\"");
                    }

                    // auto-accept the eula
                    AcceptEula();

                    break;

                case "down_nok":
                    // server-side error
                    GlobObj.OutL("Could not download hashcat: " + responze[1]);
                    return false;

                case "down_na":
                    // update required driver version
                    if (forceUpdate != "")
                        return false;
                    break;
            }
            return true;

        }

        public static void AcceptEula()
        {
            // simply create a file with accepted eula
            string eulaFile = Path.Combine(dir, "eula.accepted");
            if (!File.Exists(eulaFile))
            {
                GlobObj.OutL("Accepting EULA...");
                File.WriteAllText(eulaFile, "z\x00\x00\x00");
            }
        }

        public static bool Start(string cmdLine)
        {
            // start hashcat process

            //relative path optimization
            cmdLine = cmdLine.Replace(Dirs.install, ".." + Path.DirectorySeparatorChar);

            ProcessStartInfo pinfo = new ProcessStartInfo();
            pinfo.FileName = exe;
            pinfo.Arguments = cmdLine;

            Debug.Output(exe + " " + cmdLine, Debug.flag);

            // prepare the process
            pinfo.WorkingDirectory = Dirs.tasks;
            pinfo.UseShellExecute = false;
            pinfo.RedirectStandardError = true;
            pinfo.RedirectStandardOutput = true;

            hcProcess = new Process();
            hcProcess.StartInfo = pinfo;

            // create event handlers for normal and error output
            hcProcess.OutputDataReceived += (sender, argu) => outputNormal(argu.Data);
            hcProcess.ErrorDataReceived += (sender, argu) => outputError(argu.Data);
            hcProcess.Exited += (sender, argu) => procExit();
            hcProcess.EnableRaisingEvents = true;

            // start the process and init reading the output streams
            bool novy = hcProcess.Start();
            if (novy)
            {
                hcProcess.BeginOutputReadLine();
                hcProcess.BeginErrorReadLine();

                GlobObj.OutL(string.Format("Hashcat subprocess started at {0:HH:mm:ss}", hcProcess.StartTime));
            }
            else
            {
                GlobObj.OutL(string.Format("Hashcat subprocess didn't start at {0:HH:mm:ss}", hcProcess.StartTime));
            }
            return novy;

        }

        public static void WaitForExit()
        {
            if (!hcProcess.HasExited)
                hcProcess.WaitForExit();
        }

        public static void procExit()
        {
            exitCode = hcProcess.ExitCode;
            okExit = (exitCode >= 0 && exitCode < 128);

            TimeSpan executeSpan = hcProcess.ExitTime - hcProcess.StartTime;
            lastRun = Math.Round(executeSpan.TotalSeconds);

            // print output (including one stuffing newline)
            GlobObj.OutL(string.Format("Hashcat subprocess exited at {0:HH:mm:ss} ({1}s) with code {2}", hcProcess.StartTime, lastRun, exitCode));
        }

        public static void outputNormal(string co)
        {
            // callback for stdout
            if (co != null)
            {
                Debug.Output(co, Debug.flag);
                switch (mode)
                {
                    case 3:
                        // keyspace measuring
                        co = co.Trim();
                        long ksHelper;
                        if (long.TryParse(co, out ksHelper) && ksHelper > 0)
                        {
                            // grab the progress value and return it
                            Task.keyspace = co;
                        }
                        break;

                    case 2:
                        // benchmarking
                        co = co.Trim();
                        if (co != "")
                        {
                            if (co.StartsWith("STATUS\t"))
                            {
                                // its a progress, parse the line and get data
                                parseStatus(co);

                                // upload errors
                                WebComm.uploadErrors();
                            }
                        }
                        break;

                    case 1:
                        // cracking
                        int poz = co.LastIndexOf(Htp.separator);
                        if (poz == -1)
                        {
                            // there are no separators, its status update
                            co = co.Trim();
                            if (co != "")
                            {
                                if (co.StartsWith("STATUS\t"))
                                {
                                    // its a progress, parse the line and get data
                                    parseStatus(co);

                                    // upload errors
                                    WebComm.uploadErrors();

                                    // upload hashes only if nothing is being uploaded right now
                                    // or we are ending a chunk
                                    if (int.Parse(Chunk.status) >= 4 || Threads.ClearFinished() == 0)
                                    {
                                        WebComm.uploadHashes();
                                    }
                                }
                            }
                        }
                        else
                        {
                            // there is separator - it's cracking output
                            lock (GlobObj.lockCracked)
                            {
                                // securely add it to the buffer
                                GlobObj.crackedHashes.AppendLine(co);
                            }
                        }
                        break;
                }

            }
        }

        public static void outputError(string co)
        {
            // callback for stderr
            if (co != null)
            {
                co = co.Trim();
                if (co != "")
                {
                    // if the line is not empty then add it to the error output
                    Debug.Output(co, true, ConsoleColor.Red);
                    GlobObj.errOutput.AppendLine(co);
                }
            }
        }

        public static void parseStatus(string line)
        {
            string[] items = line.Split('\t');
            for (int i = 0; i < items.Length; i++)
            {
                switch (items[i])
                {
                    case "STATUS":
                        Chunk.status = items[1];
                        break;

                    case "SPEED":
                        decimal speed = 0, tester = 0;
                        i++;
                        do
                        {
                            decimal keys = decimal.Parse(items[i], CultureInfo.InvariantCulture);
                            decimal duration = decimal.Parse(items[i + 1], CultureInfo.InvariantCulture);
                            if (duration > 0)
                                speed += (keys / duration) * 1000;
                            i += 2;
                        } while (decimal.TryParse(items[i], out tester) == true);
                        Chunk.totalSpeed = Math.Round(speed).ToString();
                        break;

                    case "CURKU":
                        Chunk.curKUlast = Chunk.curKU;
                        Chunk.curKU = items[i + 1];
                        break;

                    case "PROGRESS":
                        Chunk.rProgress = items[i + 1];
                        Chunk.rSize = items[i + 2];
                        break;
                }
            }
        }


    }

    static class Token
    {
        public static string filename = "hashtopus.token";
        public static string value = "";

        public static bool Read()
        {
            // read token from text file
            string tok = Config.Read("token");
            if (tok == null)
            {
                return false;
            }
            else
            {
                value = tok;
                return true;
            }
        }

        public static bool Write()
        {
            // write the token to disk
            Config.Write("token", value);
            return true;
        }

        public static bool Set(string newtok)
        {
            // set new token
            value = newtok;
            return Write();
        }

        public static void Delete()
        {
            // delete bad token
            Config.Delete("token");
        }
    }

    static class Agent
    {
        public static bool logged = false;

        public static bool Register()
        {
            GlobObj.Out("Registering to server...");
            // create parameters from diagnosed values
            NameValueCollection parametry = new NameValueCollection();
            parametry.Add("uid", Htp.uid);
            parametry.Add("cpu", Htp.cpu);
            parametry.Add("name", Htp.machineName);
            parametry.Add("gpus", string.Join(Htp.separator.ToString(), Htp.gpus.ToArray()));
            parametry.Add("os", Htp.os.ToString());

            // request voucher from user
            GlobObj.Out("Enter registration voucher: ");
            string voucher = Console.ReadLine();

            parametry.Add("voucher", voucher);
            string[] responze = new string[] { };
            // send them and receive the token
            try
            {
                responze = Encoding.ASCII.GetString(WebComm.UploadValues("a=reg", parametry)).Split(Htp.separator);
            }
            catch (WebException e)
            {
                WebComm.Error(e);
                return false;
            }
            switch (responze[0])
            {
                case "reg_ok":
                    Token.Set(responze[1]);
                    GlobObj.OutL("OK.");
                    return true;

                case "reg_nok":
                    GlobObj.OutL("failed: " + responze[1]);
                    return false;

                default:
                    GlobObj.OutL("Registration to server returned nonsense.");
                    return false;
            }

        }

        public static bool Login()
        {
            if (logged)
            {
                // if already logged
                return true;
            }

            if (Token.Read())
            {
                GlobObj.Out("Logging in to server...");
                // login with provided token
                string[] responze = new string[] { };
                try
                {
                    responze = WebComm.DownloadString("a=log&token=" + Token.value).Split(Htp.separator);
                }
                catch (WebException e)
                {
                    WebComm.Error(e);
                    return false;
                }

                switch (responze[0])
                {
                    case "log_ok":
                        int newSleepTime = int.Parse(responze[1]);
                        if (newSleepTime > 0) Htp.sleepTime = newSleepTime;
                        GlobObj.OutL("OK.");
                        logged = true;
                        return true;

                    case "log_nok":
                        GlobObj.OutL("failed: " + responze[1]);
                        return false;

                    case "log_unknown":
                        GlobObj.OutL("failed: " + responze[1]);
                        Token.Delete();
                        return false;

                    default:
                        GlobObj.OutL("Logon to master server returned nonsense.");
                        return false;
                }
            }
            else
            {
                return false;
                // no more recursion here
            }
        }
    }

    static class Htp
    {
        public static string ver = "1.4";
        public static string myExe = "";
        public static string updateExe = "hashtopus-updater.exe";
        public static string logfile = "hashtopus.log";
        public static char separator = '\x01';
        public static int sleepTime = 30;
        public static string hashlistAlias = "#HL#";

        public static int os = -1;
        public static string cpu = "";
        public static string uid = "";
        public static string machineName = "";
        public static List<string> gpus = new List<string>();

        public static void detectOS()
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                // linux
                os = 1;
            }
            else
            {
                // windoze
                os = 0;
            }
        }

        public static void detectCPU()
        {
            cpu = (IntPtr.Size * 8).ToString();
        }

        public static void detectGPUs()
        {
            switch (os)
            {
                case 0:
                    // detect gpu on win
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Description FROM Win32_VideoController");
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        gpus.Add(mo.Properties["Description"].Value.ToString().Trim());
                    }
                    break;

                case 1:
                    // detect gpu on linux
                    ProcessStartInfo pinfo = new ProcessStartInfo();
                    pinfo.FileName = "lspci";
                    pinfo.UseShellExecute = false;
                    pinfo.RedirectStandardOutput = true;
                    Process lspci = new Process();
                    lspci.StartInfo = pinfo;
                    Debug.Output(pinfo.FileName + " " + pinfo.Arguments, Debug.flag);
                    lspci.Start();
                    while (!lspci.HasExited)
                    {
                        // dig through the output
                        while (!lspci.StandardOutput.EndOfStream)
                        {
                            string vystup = lspci.StandardOutput.ReadLine();
                            int pozi = vystup.IndexOf("VGA compatible controller: ");
                            if (pozi != -1)
                            {
                                gpus.Add(vystup.Substring(pozi + 27));
                            }
                        }
                    }
                    break;
            }
        }

        public static void detectName()
        {
            switch (os)
            {
                case 0:
                    machineName = Environment.MachineName;
                    break;

                case 1:
                    ProcessStartInfo pinfo = new ProcessStartInfo();
                    pinfo = new ProcessStartInfo();
                    pinfo.FileName = "uname";
                    pinfo.Arguments = "-n";
                    pinfo.UseShellExecute = false;
                    pinfo.RedirectStandardOutput = true;
                    Process uname = new Process();
                    uname.StartInfo = pinfo;
                    Debug.Output(pinfo.FileName + " " + pinfo.Arguments, Debug.flag);
                    uname.Start();
                    while (!uname.HasExited)
                    {
                        // dig through the output
                        while (!uname.StandardOutput.EndOfStream)
                        {
                            string vystup = uname.StandardOutput.ReadLine();
                            machineName = vystup;
                        }
                    }
                    break;

            }
            

        }

        public static void detectUid()
        {
            switch (os)
            {
                case 0:
                    // load unique identified (windows system hard disk serial number)
                    ManagementObject dsk = new ManagementObject("win32_logicaldisk.deviceid=\"" + Environment.SystemDirectory[0].ToString() + ":\"");
                    dsk.Get();
                    uid = dsk["VolumeSerialNumber"].ToString();
                    break;

                case 1:
                    // load unique id
                    ProcessStartInfo pinfo = new ProcessStartInfo();
                    string mtab = File.ReadAllText("/proc/mounts");
                    mtab = mtab.Replace("\t", " ");
                    mtab = mtab.Replace("  ", " ");
                    string[] radky = mtab.Split('\n');
                    string rootdrive = "";
                    foreach (string radek in radky)
                    {
                        string[] pole = radek.Split(' ');
                        if ((pole[1] == "/") && (pole[0].Contains("/")))
                        {
                            // root dir record
                            rootdrive = pole[0];
                            break;
                        }
                    }

                    if (rootdrive != "")
                    {
                        // rootdir was found in the mtab
                        if (rootdrive.Contains("uuid"))
                        {
                            // the uuid is directly in the mtab
                            uid = Path.GetFileName(rootdrive);
                        }
                        else
                        {
                            // there is a device name, we need to find its uuid
                            pinfo = new ProcessStartInfo();
                            pinfo.FileName = "blkid";
                            pinfo.Arguments = rootdrive;
                            pinfo.UseShellExecute = false;
                            pinfo.RedirectStandardOutput = true;
                            Process blkid = new Process();
                            blkid.StartInfo = pinfo;
                            Debug.Output(pinfo.FileName + " " + pinfo.Arguments, Debug.flag);

                            blkid.Start();
                            while (!blkid.HasExited)
                            {
                                // dig through the output
                                while (!blkid.StandardOutput.EndOfStream)
                                {
                                    string vystup = blkid.StandardOutput.ReadLine();
                                    if (vystup.Substring(0, rootdrive.Length) == rootdrive)
                                    {
                                        uid = vystup.Substring(vystup.IndexOf("UUID=\"") + 5);
                                        uid = uid.Substring(0, uid.IndexOf("\""));
                                        uid = uid.Replace("-", "");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (uid == null || uid == "")
                    {
                        // somehow we didn't get a UID, let's just randomly generate one
                        uid = "BADID_" + new Random().Next(999999).ToString();
                    }
                    break;
            }
        }

        public static void detectAll()
        {
            detectOS();
            detectCPU();
            detectGPUs();
            detectName();
            detectUid();
        }

        public static bool detectUrl()
        {
            // get url from xml
            string url = Config.Read("url");
            if (url == null)
            {
                // its not there
                if (HtpService.enabled)
                {
                    // exit when service
                    GlobObj.OutL("No URL is defined in config.");
                    return false;
                }
                // ask user when interactive
                Console.Write("Enter server.php URL: ");
                WebComm.root = Console.ReadLine();
                Config.Write("url", WebComm.root);
            }
            else
            {
                WebComm.root = url;
            }
            // check the URL
            string gotver = WebComm.DownloadString("a=ver");
            if (gotver != ver)
            {
                GlobObj.OutL("Incorrect URL or version mismatch: " + gotver);
                return false;
            }
            return true;
        }

        public static bool WaitForIt()
        {
            for (int i=0;i<sleepTime;i++)
            {
                if (HtpService.bw.CancellationPending) return false;
                Thread.Sleep(1000);
            }
            return true;
        }

        public static bool SelfUpdate()
        {
            // self updating procedure

            // it is started regulary
            if (File.Exists(updateExe))
            {
                // delete update exe if there was any - that means update was successful
                Threads.waitForQuit(updateExe);
                File.Delete(updateExe);
            }
            // calculate hash
            string hash = GlobObj.fileMD5(myExe);
            byte[] responze = new byte[] { };
            try
            {
                // upload it on server
                responze = WebComm.DownloadData("a=update&hash=" + hash);
            }
            catch (WebException e)
            {
                WebComm.Error(e);
                return true;
            }
            if (responze.Length >= 2 && responze[0] == 77 && responze[1] == 90)
            {
                GlobObj.Out("New Hashtopus version available: ");
                // if we got something in return its the new binary
                GlobObj.OutL("updating...");

                // write new exe
                string newExe = Path.GetFileNameWithoutExtension(myExe) + ".new";
                File.WriteAllBytes(newExe, responze);

                // write updater
                File.WriteAllBytes(updateExe, Properties.Resources.hashtopus_updater);

                Process updater = new Process();
                string arg = string.Format("\"{0}\" \"{1}\"{2}", myExe, newExe, (HtpService.enabled ? " " + Hashtopus.ServiceName : ""));
                if (os == 1)
                {
                    // on unix, we can overwrite ourselves
                    updater.StartInfo.FileName = "mono";
                    updater.StartInfo.Arguments = updateExe + " " + arg;
                }
                else
                {
                    // on windows, we must use transfer exe
                    updater.StartInfo.FileName = updateExe;
                    updater.StartInfo.Arguments = arg;
                }
                updater.StartInfo.WorkingDirectory = Dirs.install;

                Debug.Output(updater.StartInfo.FileName + " " + updater.StartInfo.Arguments, Debug.flag);
                updater.Start();
                return true;
            }
            return false;

        } 

        public static bool Init()
        {
            Dirs.Init();

            // say helo
            string verTag = string.Format("Hashtopus {0} running in {1} mode", ver, (HtpService.enabled ? "service" : "console"));
            GlobObj.OutL(verTag);

            // switch to executable directory
            Config.Init();

            // inform about debug mode state
            Debug.flag = (Config.Read("debug") == "1");
            Debug.Output("Debug mode on.", Debug.flag);

            // read url from xml or screen
            if (!detectUrl())
            {
                // exit if no url was found and could not be entered (service mode)
                return false;
            }

            // find out system internal details
            detectAll();

            return true;
        }

        public static bool Cycle()
        {
            // wait for unfinished requests from last cycle
            Threads.WaitForFinish();

            // self update hashtopus
            if (SelfUpdate())
            {
                return false;
            }

            // login to the server
            while (!Agent.Login())
            {
                // on fail, register and try again
                if (!Agent.Register())
                    if (!WaitForIt())
                        return false;

            }

            // update hashcat if needed
            while (!Hashcat.Update())
            {
                // repeat if it failed
                if (!WaitForIt())
                    return false;
            }

            // get ourselves a job!
            if (Task.Load())
            {
                uint stav = 0;
                do
                {
                    // reset variables before they will be assigned
                    Chunk.Init();

                    // load chunk from server
                    // return codes: 0=not ok, 1=ok, 2=need benchmark first, 3=need keyspace first
                    stav = Chunk.Load();

                    switch (stav)
                    {
                        case 3:
                            // we are first to be assigned to this task, so we need to calculate the keyspace
                            if (Task.calcKeyspace())
                            {
                                if (!Task.uploadKeyspace())
                                {
                                    stav = 0;
                                }
                            }
                            break;

                        case 2:
                            // we are new to this task, we need to benchmark our performance
                            if (Task.calcBenchmark())
                            {
                                if (!Task.uploadBenchmark())
                                {
                                    stav = 0;
                                }
                            }
                            break;

                        case 1:
                            // everything is OK, let's crack
                            if (Task.Start())
                            {

                                if (Chunk.rProgress == "0")
                                {
                                    // if there was no error, create one
                                    string nErr = string.Format("Hashtopus: Task didn't progress, time={0}s{1}", Hashcat.lastRun, Environment.NewLine);
                                    GlobObj.errOutput.AppendLine(nErr);
                                    stav = 0;
                                }

                                // in case there was no status update but there were hashes or errors
                                WebComm.uploadErrors();
                            }
                            else
                            {
                                // hashcat didn't even start
                                stav = 0;
                            }
                            break;
                    }
                } while (stav > 0);
            }
            else
            {
                // task assign/load failed - also no need for console output
                if (!WaitForIt())
                    return false;
            }
            return true;
        }

        public static void Run()
        {
            // init vars
            if (!Init())
                return;

            // repeat the main cycle indefinitely
            while (true)
            {
                if (!Cycle())
                    return;
            }
        }
    }

    static class Subdirs
    {
        public static string hashcat = "hashcat";
        public static string files = "files";
        public static string tasks = "tasks";
        public static string hashlists = "hashlists";
        public static string zaps = "zaps";
    }

    static class Dirs
    {
        public static string install = "";
        public static string tasks = "";
        public static string files = "";
        public static string hashlists = "";

        public static void Init()
        {
            string loc = System.Reflection.Assembly.GetEntryAssembly().Location;
            Htp.myExe = Path.GetFileName(loc);
            install = Path.GetDirectoryName(loc);
            tasks = Path.Combine(install, Subdirs.tasks);
            files = Path.Combine(install, Subdirs.files);
            hashlists = Path.Combine(install, Subdirs.hashlists);
            Directory.SetCurrentDirectory(install);
        }

        public static void CreateTasks()
        {
            if (!Directory.Exists(Dirs.tasks))
            {
                GlobObj.Out("Creating tasks directory...");
                Directory.CreateDirectory(Dirs.tasks);
                GlobObj.OutL("OK");
            }
        }

        public static void CreateHashlists()
        {
            if (!Directory.Exists(Dirs.hashlists))
            {
                GlobObj.Out("Creating hashlists directory...");
                Directory.CreateDirectory(Dirs.hashlists);
                GlobObj.OutL("OK");
            }
        }

        public static void CreateFiles()
        {
            if (!Directory.Exists(Dirs.files))
            {
                GlobObj.Out("Creating files directory...");
                Directory.CreateDirectory(Dirs.files);
                GlobObj.OutL("OK");
            }
        }
    }

    static class Hashlist
    {
        public static string id = "";
        public static string file = "";
        public static string zapDir = "";

        public static void Init(string newid)
        {
            id = newid;
            file = Path.Combine(Dirs.hashlists, id);
            zapDir = Path.Combine(Dirs.hashlists, Subdirs.zaps + id);
        }

        public static void CreateZapdir()
        {
            if (!Directory.Exists(zapDir))
            {
                GlobObj.Out("Creating hashlist zaps directory...");
                Directory.CreateDirectory(zapDir);
                GlobObj.OutL("OK");
            }
        }

        public static void EraseZapdir()
        {
            if (Directory.Exists(zapDir))
            {
                GlobObj.Out("Clearing hashlist zaps directory...");
                Directory.Delete(zapDir, true);
                GlobObj.OutL("OK");
            }
        }

        public static void Erase()
        {
            if (File.Exists(file)) File.Delete(file);
        }

        public static bool Download()
        {
            if (!File.Exists(file) || new FileInfo(file).Length == 0)
            {
                byte[] obsah;

                // download hashlist
                try
                {
                    GlobObj.Out("Downloading hashlist " + id + "...");
                    string hlUrl = string.Format("a=hashes&token={0}&hashlist={1}", Token.value, id);
                    obsah = WebComm.DownloadData(hlUrl);
                }

                catch (WebException e)
                {
                    WebComm.Error(e);
                    return false;
                }

                Stream zpole = new MemoryStream(obsah);
                StreamReader radky = new StreamReader(zpole);
                // read first line of the result
                string oneLine = radky.ReadLine();
                if (oneLine == null)
                {
                    GlobObj.OutL("hashlist is empty!");
                    return false;
                }
                else
                {
                    string[] obsah2 = oneLine.Split(Htp.separator);
                    switch (obsah2[0])
                    {
                        case "hashes_nok":
                            GlobObj.OutL("failed: " + obsah2[1]);
                            return false;

                        case "hashes_na":
                            GlobObj.OutL("hashlist is fully cracked!");
                            return false;

                        default:
                            // nothing of the above = we received raw hashlist. save it to file
                            GlobObj.OutL(obsah.Length.ToString() + " bytes");
                            File.WriteAllBytes(file, obsah);
                            break;
                    }
                }
            }
            else
            {
                GlobObj.OutL("Hashlist already exists.");
            }

            return true;
        }

    }

    static class Task
    {
        public static string benchTime = "";
        public static string id = "";
        public static int assignmentType = 0;
        public static string cmdLine = "";
        public static string statusInterval = "";
        public static int zapIterator = 0;
        public static string keyspace = "";

        public static bool Load()
        {
            lock (GlobObj.lockUpload)
            {
                Dirs.CreateTasks();

                GlobObj.Out("Loading task...");
                // reset some values
                assignmentType = 0;
                cmdLine = "";
                zapIterator = 0;

                // load task info from server
                string[] responze = new string[] { };
                try
                {
                    responze = WebComm.DownloadString("a=task&token=" + Token.value).Split(Htp.separator);
                }
                catch (WebException e)
                {
                    WebComm.Error(e);
                    return false;
                }
                switch (responze[0])
                {
                    case "task_ok":
                        id = responze[1];
                        Hashlist.Init(responze[4]);

                        // define hashlist
                        Dirs.CreateHashlists();

                        GlobObj.OutL("assigned to " + id + ", hashlist " + Hashlist.id + " (" + responze[5] + ")");

                        // set internal vars for the task
                        assignmentType = int.Parse(responze[2]);

                        if (responze[5] == "new")
                        {
                            // the task is newly assigned, we will erase every possible previous work on this task
                            Hashlist.Erase();
                        }

                        // load status interval
                        statusInterval = responze[6];

                        // now check the rest of the server message
                        if (responze.Length > 7)
                        {
                            GlobObj.OutL("Task has files:");
                            // there are some files attached to this task
                            Dirs.CreateFiles();

                            for (int i = 7; i < responze.Length; i++)
                            {
                                string nam = responze[i];
                                string fnam = Path.Combine(Dirs.files, nam);
                                GlobObj.Out("- " + nam + "...");
                                if (!File.Exists(fnam) || new FileInfo(fnam).Length == 0)
                                {
                                    // if the file doesn't exist, download it
                                    GlobObj.Out("downloading...");
                                    string fileUrl = string.Format("a=file&token={0}&task={1}&file={2}", Token.value, id, nam);
                                    if (WebComm.DownloadFile(fileUrl, fnam))
                                    {
                                        if (nam.ToLower().EndsWith(".zip"))
                                        {
                                            GlobObj.Out("unzipping...");
                                            // unpack if it's zip archive
                                            Zip.UnzipFile(fnam, Dirs.files, false);
                                            // and save space by filling the original archive with short string
                                            File.WriteAllText(fnam, "UNPACKED");
                                        }
                                        GlobObj.OutL("OK");
                                    }
                                    else
                                    {
                                        return false;
                                    }
                                }
                                else
                                {
                                    GlobObj.OutL("already exists");
                                }
                            }
                        }
                        // add paths to all existing files
                        string[] casti = responze[3].Split(' ');
                        for (int i = 0; i < casti.Length; i++)
                        {
                            string newcast = Path.Combine(Dirs.files, casti[i]);
                            if (File.Exists(newcast))
                            {
                                casti[i] = "\"" + newcast + "\"";
                            }
                        }
                        cmdLine = String.Join(" ", casti);

                        // download hashlist
                        if (!Hashlist.Download())
                            return false;

                        // create command line and replace hashlistAlias with the real hashlist
                        cmdLine = cmdLine.Replace(Htp.hashlistAlias, "\"" + Hashlist.file + "\"");
                        return true;

                    case "task_nok":
                        GlobObj.OutL("failed: " + responze[1]);
                        return false;

                    default:
                        GlobObj.OutL("Task assignment returned nonsense.");
                        return false;
                }
            }
        }

        public static bool calcKeyspace()
        {
            // server requested keyspace calculation
            GlobObj.OutL("Calculating keyspace...");

            // run it and capture output
            Hashcat.mode = 3;
            string cmdAdd = string.Format("{0} --session=hashtopus --keyspace --quiet", cmdLine);
            Hashcat.Start(cmdAdd);
            Hashcat.WaitForExit();

            // upload errors that showed up
            WebComm.uploadErrorsAsync();

            if (Hashcat.okExit)
            {
                if (!string.IsNullOrEmpty(keyspace))
                {
                    // keyspace calculated
                    GlobObj.OutL(string.Format("Calculated keyspace size of {0}.", keyspace));
                    return true;
                }
                else
                {
                    // we calculated nothing
                    GlobObj.OutL("Could not calculate keyspace.");
                    return false;
                }
            } else
            {
                // hashcat crashed
                return false;
            }
        }

        public static bool uploadKeyspace()
        {
            // upload benchmark results to server
            GlobObj.Out("Uploading keyspace size...");
            string[] responze = new string[] { };
            try
            {
                string kspcUrl = string.Format("a=keyspace&token={0}&task={1}&keyspace={2}", Token.value, Task.id, keyspace);
                responze = WebComm.DownloadString(kspcUrl).Split(Htp.separator);
            }
            catch (WebException e)
            {
                WebComm.Error(e);
                return false;
            }
            switch (responze[0])
            {
                case "keyspace_ok":
                    GlobObj.OutL("Accepted");
                    return true;

                case "keyspace_nok":
                    GlobObj.OutL("Declined: " + responze[1]);
                    return false;

                default:
                    GlobObj.OutL("Keyspace submission returned nonsense.");
                    return false;
            }

        }

        public static bool calcBenchmark()
        {
            // server requested a benchmark, just run it and upload results
            GlobObj.OutL("Benchmarking task for " + benchTime + "s...");

            // reset the values
            Chunk.Init();

            // run it and capture output
            Hashcat.mode = 2;
            string cmdAdd = string.Format("{0} --runtime={1} --separator={2} --outfile=bench{3}.tmp --restore-disable --potfile-disable --machine-readable --session=hashtopus", cmdLine, benchTime, Htp.separator, id);
            Hashcat.Start(cmdAdd);
            Hashcat.WaitForExit();

            // upload errors that showed up
            WebComm.uploadErrorsAsync();

            // cleanup
            string tmpfile = Path.Combine(Dirs.tasks, string.Format("bench{0}.tmp", id));
            if (File.Exists(tmpfile)) File.Delete(tmpfile);

            if (Hashcat.okExit)
            {
                if (Chunk.rProgress != "0" && Chunk.rSize != "0")
                {
                    // keyspace calculated
                    GlobObj.OutL(string.Format("Managed to scan {0}/{1} of keyspace.", Chunk.rProgress, Chunk.rSize));
                    return true;
                }
                else
                {
                    // we calculated nothing
                    GlobObj.OutL("Could not benchmark task.");
                    return false;
                }
            }
            else
            {
                // hashcat crashed
                return false;
            }
        }

        public static bool uploadBenchmark()
        {
            // upload benchmark results to server
            GlobObj.OutL("Uploading benchmark result...");
            string[] responze = new string[] { };
            try
            {
                string bnchUrl = string.Format("a=bench&token={0}&task={1}&progress={2}&total={3}&state={4}", Token.value, Task.id, Chunk.rProgress, Chunk.rSize, Chunk.status);
                responze = WebComm.DownloadString(bnchUrl).Split(Htp.separator);
            }
            catch (WebException e)
            {
                WebComm.Error(e);
                return false;
            }
            switch (responze[0])
            {
                case "bench_ok":
                    GlobObj.OutL("Accepted (" + responze[1] + ")");
                    return true;

                case "bench_nok":
                    GlobObj.OutL("Declined: " + responze[1]);
                    return false;

                default:
                    GlobObj.OutL("Benchmark submission returned nonsense.");
                    return false;
            }
        }

        public static bool Start()
        {
            // actual start of the cracking process
            GlobObj.OutL("Starting task cracking...");

            // reset the values
            Chunk.InitProg();
            // also create directory for zaps, should it not exist
            Hashlist.EraseZapdir();
            Hashlist.CreateZapdir();


            // run it and capture output
            Hashcat.mode = 1;
            string cmdAdd = string.Format("{0} --potfile-disable --quiet --restore-disable --session=hashtopus --status --machine-readable --status-timer={1} --outfile-check-dir=\"{2}\" --outfile-check-timer={1} --remove --remove-timer={1} --separator={3} --skip={4} --limit={5}", cmdLine, statusInterval, Hashlist.zapDir, Htp.separator, Chunk.start, Chunk.size);
            bool vysledek = Hashcat.Start(cmdAdd);
            Hashcat.WaitForExit();
            return vysledek;

        }
    }
    
    static class Debug
    {
        public static bool flag = false;
        public static void Output(string toPrint, bool debugFlag, ConsoleColor printColor = ConsoleColor.Magenta)
        {
            if (debugFlag)
            {
                Console.ForegroundColor = printColor;
                GlobObj.OutL(toPrint);
                Console.ResetColor();
            }
        }
    }

    static class WebComm
    {
        public static int progresHelper = 0;
        public static string root = "";

        public static void Error(WebException e)
        {
            // just printout http error
            Debug.Output("HTTP error: " + e.Message, true);
        }

        public static bool DownloadFile(string qsa, string local)
        {
            // launch async file downloading and report progress
            WebClient wcli = new WebClient();
            Uri adresa = new Uri(string.Format("{0}?{1}", root, qsa));
            ServicePoint wcsp = ServicePointManager.FindServicePoint(adresa);
            wcsp.Expect100Continue = false;

            // create the event handler
            wcli.DownloadProgressChanged += (sender, e) =>
            {
                lock (GlobObj.lockProgress)
                {
                    // don't display the same number twice
                    int progres = e.ProgressPercentage;
                    if (progres != progresHelper)
                    {
                        if (progres % 10 == 0)
                        {
                            GlobObj.Out(progres.ToString() + "% ");
                        }
                        progresHelper = progres;
                    }
                }
            };

            // download the file
            try
            {
                wcli.DownloadFileAsync(adresa, local);
            }
            catch (WebException e)
            {
                Error(e);
                return false;
            }
            while (wcli.IsBusy) Thread.Sleep(100);
            GlobObj.OutL();
            return File.Exists(local);
        }

        public static byte[] DownloadData(string qsa)
        {
            WebClient wcli = new WebClient();
            return wcli.DownloadData(string.Format("{0}?{1}", root, qsa));
        }

        public static string DownloadString(string qsa)
        {
            WebClient wcli = new WebClient();
            return wcli.DownloadString(string.Format("{0}?{1}", root, qsa));
        }

        public static byte[] UploadValues(string qsa, NameValueCollection parametry )
        {
            WebClient wcli = new WebClient();
            return wcli.UploadValues(string.Format("{0}?{1}", root, qsa), parametry);
        }

        public static void uploadErrors()
        {
            if (GlobObj.errOutput.Length == 0) return;
            // start the upload process in a new thread
            ThreadStart ts = new ThreadStart(uploadErrorsAsync);
            Thread thr = new Thread(ts);
            Threads.list.Add(thr);
            thr.Start();
        }

        public static void uploadErrorsAsync()
        {
            if (GlobObj.errOutput.Length == 0) return;

            // cycle error data structures
            string errorsToUpload = GlobObj.errOutput.ToString();
            GlobObj.errOutput = new StringBuilder();

            // define new webrequest
            string errUrl = string.Format("{0}?a=err&token={1}&task={2}", root, Token.value, Task.id);
            HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(errUrl);
            wr.Method = "POST";
            wr.ServicePoint.Expect100Continue = false;
            byte[] erej = Encoding.ASCII.GetBytes(errorsToUpload);

            // write data to the stream
            GlobObj.Out("[ERR] Uploading " + erej.Length.ToString() + " b...");
            Stream wrStream = wr.GetRequestStream();
            wrStream.Write(erej, 0, erej.Length);
            wrStream.Close();

            // read the response
            HttpWebResponse wrs = (HttpWebResponse)wr.GetResponse();

            if (wrs.StatusCode != HttpStatusCode.OK)
            {
                GlobObj.OutL("ERROR " + wrs.StatusDescription);
                return;
            }

            // read the data inside the response
            Stream wrsStream = wrs.GetResponseStream();
            StreamReader radky = new StreamReader(wrsStream);

            // read first line and parse it
            string oneLine = radky.ReadToEnd();
            string[] responze = oneLine.Split(Htp.separator);

            string consOut;
            switch (responze[0])
            {
                case "err_ok":
                    consOut = string.Format("Uploaded {0} errors", responze[1]);
                    break;

                case "err_nok":
                    consOut = string.Format("ERROR: {0}", responze[1]);
                    break;

                default:
                    consOut = string.Format("HTTP >> {0}", oneLine);
                    break;
            }
            GlobObj.OutL(consOut);
            // let the response stream rest in peace
            radky.Close();
        }

        public static void uploadHashes()
        {
            // start the upload process in a new thread
            ThreadStart ts = new ThreadStart(uploadHashesAsync);
            Thread thr = new Thread(ts);
            Threads.list.Add(thr);
            thr.Start();
        }

        public static void uploadHashesAsync()
        {
            lock (GlobObj.lockUpload)
            {
                // cache data structure
                string hashesToUpload;
                lock (GlobObj.lockCracked)
                {
                    hashesToUpload = GlobObj.crackedHashes.ToString();
                    GlobObj.crackedHashes = new StringBuilder();
                }

                // define new webrequest
                string repUrl = string.Format("{0}?a=solve&token={1}&chunk={2}&curku={3}&speed={4}&progress={5}&total={6}&state={7}", root, Token.value, Chunk.id, Chunk.curKU, Chunk.totalSpeed, Chunk.rProgress, Chunk.rSize, Chunk.status);
                HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(repUrl);
                wr.Method = "POST";
                wr.Timeout = int.MaxValue;
                wr.ServicePoint.Expect100Continue = false;
                byte[] erej = Encoding.ASCII.GetBytes(hashesToUpload);

                // print the progress
                GlobObj.Out(string.Format("[{0}/{1}] Uploading {2} b", Chunk.rProgress, Chunk.rSize, erej.Length));

                // write data to the stream
                StreamReader radky = null;
                try
                {
                    Stream wrStream = wr.GetRequestStream();
                    wrStream.Write(erej, 0, erej.Length);
                    wrStream.Close();
                    GlobObj.Out(".");

                    // read the response
                    HttpWebResponse wrs = (HttpWebResponse)wr.GetResponse();
                    GlobObj.Out(".");

                    if (wrs.StatusCode != HttpStatusCode.OK)
                    {
                        GlobObj.OutL("ERROR " + wrs.StatusDescription);
                        return;
                    }

                    // read the data inside the response
                    Stream wrsStream = wrs.GetResponseStream();
                    radky = new StreamReader(wrsStream);
                    GlobObj.Out(".");
                }

                catch (WebException e)
                {
                    WebComm.Error(e);
                    // put back the hashes so they will be uploaded next time
                    if (hashesToUpload.Length > 0)
                    {
                        lock (GlobObj.lockCracked)
                        {
                            GlobObj.crackedHashes.Append(hashesToUpload);
                        }
                    }
                    return;
                }

                long solved = 0, zapped = 0;
                if (!radky.EndOfStream)
                {
                    // read first line and parse it
                    string oneLine = radky.ReadLine();
                    string[] responze = oneLine.Split(Htp.separator);

                    switch (responze[0])
                    {
                        case "solve_ok":
                            // save how many hashes the server marked as cracked
                            solved = long.Parse(responze[1]);
                            GlobObj.Out("Cracked " + responze[1]);
                            long skipped = long.Parse(responze[2]);
                            if (skipped > 0)
                            {
                                GlobObj.Out(", ");
                                GlobObj.Out("skipped " + responze[2]);
                            }
                            break;

                        case "solve_nok":
                            GlobObj.OutL("ERROR: " + responze[1]);
                            // terminate the hashcat process to prevent wasted work
                            if (!Hashcat.hcProcess.HasExited) Hashcat.hcProcess.Kill();
                            break;

                        default:
                            GlobObj.OutL("HTTP >> " + oneLine);
                            break;
                    }

                    if (responze.Length >= 4)
                    {
                        // if the message goes on
                        if (responze[3] == "zap_ok")
                        {
                            // following are the zaps

                            // create a new file
                            string tmpFile = Path.Combine(Dirs.tasks, "zaps.tmp");

                            // create a temp file outside scanned directory
                            StreamWriter saveZaps = new StreamWriter(tmpFile);
                            Task.zapIterator++;
                            while (true)
                            {
                                // keep reading non empty lines
                                oneLine = radky.ReadLine();
                                if (oneLine == null) break;
                                // write the zap
                                zapped++;
                                saveZaps.WriteLine(oneLine + Htp.separator);
                            }
                            // close the file
                            saveZaps.Close();
                            // move the file to scanned directory
                            string finalfn = string.Format("zaps{0}.txt", Task.zapIterator);
                            string finalFile = Path.Combine(Hashlist.zapDir, finalfn);
                            File.Move(tmpFile, finalFile);
                            // return how many zaps were written
                            GlobObj.Out(string.Format(", zapped {0}/{1}", zapped, responze[4]));
                        }

                        if (responze[3] == "stop")
                        {
                            // the hashlist was fully cracked, no need to continue working
                            GlobObj.Out(", hashlist cracked!");
                            zapped++;
                            if (!Hashcat.hcProcess.HasExited) Hashcat.hcProcess.Kill();
                        }

                    }
                }
                // let the response stream rest in peace
                radky.Close();

                // write a star if something was done
                if (solved + zapped > 0)
                {
                    GlobObj.Out(" [*]");
                }
                GlobObj.OutL();
            }
        }
    }

    static class GlobObj
    {
        public static object lockUpload = new object();
        public static object lockProgress = new object();
        public static object lockCracked = new object();
        public static object lockLog = new object();
        public static StringBuilder crackedHashes = new StringBuilder();
        public static StringBuilder errOutput = new StringBuilder();
        public static bool nlEnded = true;

        public static string fileMD5(string fileName)
        {
            // calculate md5 checksum of a file
            MD5 hasher = MD5.Create();
            return BitConverter.ToString(hasher.ComputeHash(File.ReadAllBytes(fileName))).Replace("-", "").ToLower();
        }

        public static void Out(string co)
        {
            lock (lockLog)
            {
                if (HtpService.enabled)
                {
                    if (nlEnded)
                    {
                        // only produce timestamps on new line
                        File.AppendAllText(Htp.logfile, string.Format("[{0:dd/MM/yyyy, HH:mm:ss}] ", DateTime.Now));
                    }
                    File.AppendAllText(Htp.logfile, co);
                }
                else
                {
                    Console.Write(co);
                }
            }
            nlEnded = false;
        }

        public static void OutL(string co = "")
        {
            Out(co + Environment.NewLine);
            nlEnded = true;
        }

    }

    static class Zip
    {
        public static void UnzipFile(string archive, string target, bool preservePaths = true)
        {
            ZipStorer zip = ZipStorer.Open(archive);
            List<ZipStorer.ZipFileEntry> dir = zip.ReadCentralDir();
            string finalfile;
            foreach (ZipStorer.ZipFileEntry entry in dir)
            {
                string filename = entry.FilenameInZip;
                if (!preservePaths) filename = Path.GetFileName(filename);
                finalfile = Path.Combine(target, filename);
                zip.ExtractFile(entry, finalfile);
                // if the extracted file is also a zip, then unzip it as well (multilevel zip)
                if (finalfile.ToLower().EndsWith(".zip")) UnzipFile(finalfile, target, preservePaths);
            }
            zip.Close();
        }
    }

    static class Threads
    {
        public static List<Thread> list = new List<Thread>();

        public static int ClearFinished()
        {
            list.RemoveAll(jeden => jeden.IsAlive == false);
            return list.Count;
        }

        public static void WaitForFinish()
        {
            bool informed = false;
            while (true)
            {
                // delete all finished threads
                if (ClearFinished() > 0)
                {
                    if (!informed)
                    {
                        GlobObj.Out("Waiting for unfinished HTTP connections...");
                        informed = true;
                    }
                    Thread.Sleep(100);
                }
                else
                {
                    break;
                }
            }
            if (informed) GlobObj.OutL("OK");
        }

        public static void waitForQuit(string procname)
        {
            // keep waiting 100 ms until desired process exits
            do
            {
                Thread.Sleep(100);
            } while (IsRunning(procname));
        }

        public static bool IsRunning(string procname)
        {
            // is process running?
            Process[] bezi;
            bezi = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(procname));
            return (bezi.Length > 0);
        }

    }

    static class HtpService
    {
        public static bool enabled = false;
        public static BackgroundWorker bw = new BackgroundWorker();
        public static AutoResetEvent rst = new AutoResetEvent(false);

        public static void Start(string[] args)
        {
            bw.WorkerSupportsCancellation = true;
            bw.DoWork += (sender, argz) =>
            {
                Htp.Run();
            };

            bw.RunWorkerCompleted += (sender, argz) =>
            {
                rst.Set();
            };

            bw.RunWorkerAsync();
        }

        public static void Stop()
        {
            bw.CancelAsync();
        }

    }

    static class Config
    {
        public static string file = "";
        public static XmlDocument xd = new XmlDocument();
        public static XmlElement xr;

        public static void Init()
        {
            file = Path.Combine(Dirs.install, "hashtopus.xml");
            if (File.Exists(file))
            {
                Debug.Output("Loading existing config XML", Debug.flag);
                xd.Load(file);
                xr = xd.DocumentElement;
            }
            else
            {
                Debug.Output("Creating new config XML", Debug.flag);
                xr = xd.CreateElement("Hashtopus");
                xd.AppendChild(xr);
            }
            xd.Save(file);
        }

        public static void Delete(string att)
        {
            Debug.Output("Deleting XML element " + att, Debug.flag);
            XmlNodeList nl = xr.GetElementsByTagName(att);
            foreach (XmlNode xn in nl)
            {
                xr.RemoveChild(xn);
            }
            xd.Save(file);
        }

        public static void Write(string att, string val)
        {
            Debug.Output("Writing XML element " + att, Debug.flag);
            XmlNodeList nl = xr.GetElementsByTagName(att);
            if (nl.Count > 0)
            {
                nl[0].InnerText = val;
            }
            else
            {
                XmlElement xn = xd.CreateElement(att);
                xn.InnerText = val;
                xr.AppendChild(xn);
            }
            xd.Save(file);
        }

        public static string Read(string att)
        {
            Debug.Output("Reading XML element " + att, Debug.flag);
            XmlNodeList nl = xr.GetElementsByTagName(att);
            if (nl.Count > 0)
            {
                return nl[0].InnerText;
            }
            else
            {
                return null;
            }
        }

    }


}
