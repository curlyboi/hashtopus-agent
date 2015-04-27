using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Management;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Net;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security.Cryptography;
using System.Globalization;


[StructLayout(LayoutKind.Sequential)]
struct LASTINPUTINFO
{
    public static readonly int SizeOf = Marshal.SizeOf(typeof(LASTINPUTINFO));

    [MarshalAs(UnmanagedType.U4)]
    public UInt32 cbSize;
    [MarshalAs(UnmanagedType.U4)]
    public UInt32 dwTime;
}

namespace hashtopus
{
    class hashtopus
    {

        [DllImport("user32.dll")]
        public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FreeLibrary(IntPtr hModule);

        public static bool debug = false;

        public static string htpver = "0.9.4";
        public static char separator = '\x01';
        public static string goodExe = "hashtopus.exe";
        public static string updateExe = "hashtopupd.exe";
        public static string[] arguments;

        public static bool eventmode = false;
        public static string readyfile = "event_ready";
        public static string idlefile = "event_idle";
        public static bool eventhelper = false;

        public static string hcSubdir = "hashcat";
        public static string filesSubdir = "files";
        public static string tasksSubdir = "tasks";
        public static string hashlistSubdir = "hashlists";
        public static string zapsSubdir = "zaps";

        public static string hashlistAlias = "#HL#";
        public static int sleepTime = 30000;

        public static string webroot;
        public static string installPath;

        public static int os;
        public static string cpu;
        public static string uid;
        public static string machineName;
        public static string gpus;
        public static string gpubrand;
        public static long curVer;

        public static string token;
        public static string tokenName = "hashtopus.token";
        public static string tokenFile;

        public static string hcDir = "";
        public static string tasksDir = "";
        public static string filesDir = "";
        public static string hashlistDir = "";
        public static string cmdExecutable;
        
        public static string benchTime;

        public static string task = "";
        public static string zapDir = "";
        public static string hashList = "";
        public static string hashListFile = "";
        public static int assignmentType;
        public static string cmdLine;
        public static string statusInterval;
        
        public static int zapIterator;

        public static string chunkStart;
        public static string chunkSize;
        public static string chunkId;
        public static string chunkStatus;
        public static string chunkCurKU;
        public static string chunkCurKUlast;
        public static string chunkRProgress;
        public static string chunkRSize;
        public static string totalSpeed;
        
        public static StringBuilder crackedHashes = new StringBuilder();
        public static StringBuilder errOutput = new StringBuilder();
        public static Process hashcatProcess;

        public static object uploadHashesLock = new object();
        public static object progressLock = new object();
        public static object crackedLock = new object();

        public static List<Thread> threadList = new List<Thread>();

        public static int progresHelper = 0;


        public static void debugOutput(string toPrint, bool debugFlag, ConsoleColor printColor = ConsoleColor.Magenta)
        {
            if (debugFlag)
            {
                ConsoleColor originalColor = Console.ForegroundColor;
                Console.ForegroundColor = printColor;
                Console.WriteLine(toPrint);
                Console.ForegroundColor = originalColor;
            }
        }
        
        public static void webError(WebException e)
        {
            // just printout http error

            debugOutput("HTTP error: " + e.Message, true);
        }

        static void Main(string[] args)
        {
            arguments = args;

            // switch to executable directory
            installPath = AppDomain.CurrentDomain.BaseDirectory;
            Directory.SetCurrentDirectory(installPath);
            tokenFile = Path.Combine(installPath, tokenName);
            
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

            Console.Title = "Hashtopus " + htpver;
            Console.WriteLine(Console.Title);
            
            if (Array.IndexOf(arguments, "debug") > -1)
            {
                Console.WriteLine("Debug mode on.");
                debug = true;
            }

            if (Array.IndexOf(arguments, "eventmode") > -1) eventmode = true;
            
            // ENTRY POINT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

            // read the executable for connector URL
            if (!findUrl())
            {
                Console.WriteLine("No URL found in this executable. Please deploy agent properly from administration.");
                return;
            }
            
            // find out system internal details
            diagnoseSystem();

            // construct bunch of dirs
            hcDir = Path.Combine(installPath, hcSubdir);
            tasksDir = Path.Combine(installPath, tasksSubdir);
            filesDir = Path.Combine(installPath, filesSubdir);
            hashlistDir = Path.Combine(installPath, hashlistSubdir);

            while (!loginAgent())
            {
                // try to login in 30s intervals
                Thread.Sleep(sleepTime);
            }

            // MAIN CYCLE START
            do
            {
                // self update hashtopus
                selfUpdate();

                // determine gpu driver version
                while (!versionDetect())
                {
                    // repeat untill if passes
                    Thread.Sleep(sleepTime);
                }

                // update hashcat if needed
                while (!downloadHashcat())
                {
                    // repeat if it failed
                    Thread.Sleep(sleepTime);
                }

                // auto-accept the eula
                acceptEula();

                // wait for unfinished requests
                waitForThreads();
                
                // get ourselves a job!
                if (loadTask())
                {
                    // wait for inactivity or event file
                    waitForIdle();

                    // reset variables before they will be assigned
                    chunkStart = "0";
                    chunkSize = "0";
                    chunkId = "0";

                    // load chunk from server
                    // return codes: 0=not ok, 1=ok, 2=need benchmark first, 3=need keyspace first
                    uint stav = loadTaskChunk();

                    if (stav == 3)
                    {
                        // keyspace measuring before chunk acquisition
                        string keyspace = measureTaskKeyspace();
                        // upload the results
                        if (keyspace != "" && submitKeyspace(keyspace))
                        {
                            // result uploaded ok,
                            // re-try chunk load
                            stav = loadTaskChunk();
                        }
                        else
                        {
                            // benchmark result upload failed - take it as if chunk acquisition failed
                            stav = 0;
                        }
                    }

                    if (stav == 2)
                    {
                        // benchmark needed before chunk acquisition
                        // start the benchmark
                        chunkRProgress = "0";
                        chunkRSize = "0";
                        benchTask();
                        // upload the results
                        if (chunkRProgress != "0" && chunkRSize != "0" && submitBench())
                        {
                            // result uploaded ok,
                            // re-try chunk load
                            stav = loadTaskChunk();
                        }
                        else
                        {
                            // benchmark result upload failed - take it as if chunk acquisition failed
                            stav = 0;
                        }
                    }

                    if (stav == 1)
                    {
                        // chunk loaded ok (no matter if there was benchmark beforehand)
                        // start hashcat process
                        chunkRProgress = "0";
                        chunkRSize = "0";
                        if (startHashcat())
                        {
                            Console.WriteLine("Hashcat subprocess started at " + hashcatProcess.StartTime.ToString("HH:mm:ss"));
                            hashcatProcess.WaitForExit();

                            int code = hashcatProcess.ExitCode;
                            //if (code < 0 || code > 128)
                            //{
                            //    errOutput.AppendLine("Hashcat process (" + hashcatProcess.StartInfo.Arguments + ") exited with return code " + code.ToString());
                            //}

                            // calculate execution time
                            TimeSpan executeSpan = hashcatProcess.ExitTime - hashcatProcess.StartTime;
                            string rozdil = Math.Round(executeSpan.TotalSeconds).ToString();

                            // print output (including one stuffing newline)
                            Console.WriteLine("Hashcat subprocess finished at " + hashcatProcess.ExitTime.ToString("HH:mm:ss") + " (" + rozdil + "s)");

                            if (chunkRProgress == "0")
                            {
                                // if there was no error, create one
                                errOutput.AppendLine("Hashtopus: Task didn't progress, time=" + rozdil + "s" + Environment.NewLine);
                            }

                            // in case there was no status update but there were hashes or errors
                            uploadErrors();

                        }
                        else
                        {
                            // hashcat couldn't be started at all
                            Console.WriteLine("Error starting hashcat!");
                        }
                    }
                    //else
                    //{
                    //    // chunk problem, let's wait
                    //    //Thread.Sleep(sleepTime);
                    //    // ACTUALLY: let's not wait, it means the cluster has moved on to a next task
                    //}

                }
                else
                {
                    // task assign/load failed - also no need for console output
                    if (!eventhelper)
                    {
                        eventhelper = true;
                        Console.WriteLine("Waiting for next assignment...");
                        if (eventmode)
                        {
                            File.WriteAllText(idlefile, "No more work to do.");
                        }
                    }
                    Thread.Sleep(sleepTime);
                }
                // repeat indefinitely
            } while (true);
        }

        public static bool findUrl()
        {
            // read my own executable and extract the path that is appended to the end of it
            string myself = AppDomain.CurrentDomain.FriendlyName;
            byte[] url = File.ReadAllBytes(myself);
            long poz = url.Length - 1;
            while (url[poz] > 0)
            {
                poz--;
            }
            long delka = url.Length - poz - 1;
            if (delka > 0)
            {
                byte[] webrootHelper = new byte[delka];
                Array.Copy(url, poz + 1, webrootHelper, 0, delka);
                webroot = Encoding.ASCII.GetString(webrootHelper);
            }
            return (delka > 0);
        }
        public static void diagnoseSystem()
        {
            // prepare structures
            List<string> gpucka = new List<string>();

            // load CPU architecture
            cpu = (IntPtr.Size * 8).ToString();
            
            // detect OS
            if (os == 1)
            {
                // unix
                // load GPUs
                ProcessStartInfo pinfo = new ProcessStartInfo();
                pinfo.FileName = "lspci";
                pinfo.UseShellExecute = false;
                pinfo.RedirectStandardOutput = true;
                Process lspci = new Process();
                lspci.StartInfo = pinfo;
                debugOutput(pinfo.FileName + " " + pinfo.Arguments, debug);
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
                            gpucka.Add(vystup.Substring(pozi + 27));
                        }
                    }
                }

                // load machine name
                pinfo = new ProcessStartInfo();
                pinfo.FileName = "uname";
                pinfo.Arguments = "-n";
                pinfo.UseShellExecute = false;
                pinfo.RedirectStandardOutput = true;
                Process uname = new Process();
                uname.StartInfo = pinfo;
                debugOutput(pinfo.FileName + " " + pinfo.Arguments, debug);
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

                // load unique id
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
                        debugOutput(pinfo.FileName + " " + pinfo.Arguments, debug);
                        
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

            }
            else
            {
                // windows
                // load GPUs into list
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Description FROM Win32_VideoController");
                foreach (ManagementObject mo in searcher.Get())
                {
                    gpucka.Add(mo.Properties["Description"].Value.ToString().Trim());
                }

                // load unique identified (windows system hard disk serial number)
                ManagementObject dsk = new ManagementObject("win32_logicaldisk.deviceid=\"" + Environment.SystemDirectory[0].ToString() + ":\"");
                dsk.Get();
                uid = dsk["VolumeSerialNumber"].ToString();

                // load machine name
                machineName = Environment.MachineName;
            }

            // concat it with separator
            gpus = String.Join(separator.ToString(), gpucka.ToArray());
        }

        public static bool registerAgent()
        {
            Console.Write("Registering to server...");
            // create parameters from diagnosed values
            NameValueCollection parametry = new NameValueCollection();
            parametry.Add("uid", uid);
            parametry.Add("cpu", cpu);
            parametry.Add("name", machineName);
            parametry.Add("gpus", gpus);
            parametry.Add("os", os.ToString());
            
            // request voucher from user
            Console.Write("Enter registration voucher: ");
            string voucher = Console.ReadLine();
            
            parametry.Add("voucher", voucher);
            string[] responze = new string[] { };
            // send them and receive the token
            try
            {
                responze = Encoding.ASCII.GetString(new WebClient().UploadValues(new Uri(webroot + "?a=reg"), parametry)).Split(separator);
            }
            catch (WebException e)
            {
                webError(e);
                return false;
            }
            switch (responze[0])
            {
                case "reg_ok":
                    token = responze[1];
                    writeToken();
                    Console.WriteLine("OK.");
                    return true;

                case "reg_nok":
                    Console.WriteLine("failed: " + responze[1]);
                    return false;

                default:
                    Console.WriteLine("Registration to server returned nonsense.");
                    return false;
            }
        }

        public static bool loginAgent()
        {
            if (readToken())
            {
                Console.Write("Logging in to server...");
                // login with provided token
                string[] responze = new string[] { };
                try
                {
                    responze = new WebClient().DownloadString(new Uri(webroot + "?a=log&token=" + token)).Split(separator);
                }
                catch (WebException e)
                {
                    webError(e);
                    return false;
                }

                switch (responze[0])
                {
                    case "log_ok":
                        gpubrand = responze[1];
                        int newSleepTime = int.Parse(responze[2]) * 1000;
                        if (newSleepTime > 0) sleepTime = newSleepTime;
                        Console.WriteLine("OK.");
                        return true;

                    case "log_nok":
                        Console.WriteLine("failed: " + responze[1]);
                        return false;

                    case "log_unknown":
                        Console.WriteLine("failed: " + responze[1]);
                        File.Delete(tokenFile);
                        return false;

                    default:
                        Console.WriteLine("Logon to master server returned nonsense.");
                        return false;
                }
            }
            else
            {
                if (registerAgent())
                {
                    return loginAgent();
                }
                else
                {
                    return false;
                }
            }
        }

        public static bool readToken()
        {
            // read token from text file
            if (File.Exists(tokenFile))
            {
                // save it into variable
                token = File.ReadAllText(tokenFile);
                return true;
            }
            else
            {
                // or return false if there is none
                return false;
            }
        }
        
        public static bool writeToken()
        {
            // write the token to disk
            File.WriteAllText(tokenFile, token);
            return true;
        }

        public static bool versionDetect()
        {
            // check if gpu driver has sufficient version
            
            if (os == 1)
            {
                debugOutput("Linux OS detected.", debug);
                // linux branch
                switch (gpubrand)
                {
                    case "1":
                        // nvidia detect
                       debugOutput("NVidia detected.", debug);
                        string nvver = "/proc/driver/nvidia/version";
                        if (File.Exists(nvver))
                        {
                            string[] verze = File.ReadAllText(nvver).Split('\n');
                            foreach (string verline in verze)
                            {
                                if ((verline.Length >= 4) && (verline.Substring(0, 4) == "NVRM"))
                                {
                                    // this is the line we want
                                    // overloaded split by string (woooo nice hax :D)
                                    debugOutput("Parsing driver version from '" + verline + "'", debug);
                                    string[] pole = verline.Split(new string[] { "  " }, StringSplitOptions.None);
                                    curVer = long.Parse(pole[1].Replace(".", ""));
                                }
                            }
                            if (curVer == 0)
                            {
                                Console.WriteLine("Could not obtain NVidia driver version.");
                                return false;
                            }
                        }
                        else
                        {
                            Console.WriteLine("Please (re)install NVidia drivers.");
                            return false;
                        }
                        break;

                    case "2":
                        // amd, read text file or assume 9999
                        debugOutput("AMD detected.", debug);
                        if (File.Exists("catalyst_ver.txt"))
                        {
                            curVer = long.Parse(File.ReadAllText("catalyst_ver.txt").Trim());
                        }
                        else
                        {
                            // there is no reliable way to find out catalyst version from linux system
                            // we need user assistance
                            Console.WriteLine("Please create file 'catalyst_ver.txt' in Hashtopus directory containing installed Catalyst version in raw number format (i.e. 1312, 1403, etc.)");
                            curVer = 0;
                        }
                        break;
                }
            }
            else
            {
                // windows version
                debugOutput("Windows OS detected.", debug);
                List<string> dlltocheck = new List<string>();
                switch (gpubrand)
                {
                    case "1":
                        debugOutput("NVidia detected.", debug);
                        if (cpu == "32")
                        {
                            dlltocheck.Add("nvapi.dll");
                        }
                        else if (cpu == "64")
                        {
                            dlltocheck.Add("nvapi64.dll");
                        }
                        dlltocheck.Add("nvcuda.dll");
                        if (!versionDetectDLLs(dlltocheck))
                        {
                            Console.WriteLine("Please (re)install NVidia drivers.");
                            return false;
                        }

                        // detect version of nvidia DLL
                        FileVersionInfo finfo = FileVersionInfo.GetVersionInfo(Path.Combine(Environment.SystemDirectory, dlltocheck[0]));
                        curVer = ((finfo.ProductBuildPart - 10) * 10000) + finfo.ProductPrivatePart;
                        break;

                    case "2":
                        debugOutput("AMD detected.", debug);
                        if (cpu == "32")
                        {
                            dlltocheck.Add("atiadlxy.dll");
                        }
                        else if (cpu == "64")
                        {
                            dlltocheck.Add("atiadlxx.dll");
                        }
                        dlltocheck.Add("OpenCL.dll");
                        if (!versionDetectDLLs(dlltocheck))
                        {
                            Console.WriteLine("Please (re)install AMD Catalyst.");
                            return false;
                        }

                        // determine version from registry key
                        RegistryKey klic = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}", false);
                        string valueToFind = "Catalyst_Version";
                        long greatestFound = 0;
                        if (klic == null)
                        {
                            Console.WriteLine("Could not access GPU registry key.");
                            return false;
                        }
                        else
                        {
                            // list all subkeys (e.g. graphic cards entries 0000, 0001 and so on)
                            foreach (string grafika in klic.GetSubKeyNames())
                            {
                                bool valueExists = false;
                                RegistryKey klicGpu = null;
                                try
                                {
                                    klicGpu = klic.OpenSubKey(grafika, false);
                                }
                                catch
                                {
                                    // do nothing - this is here because Properties subkey can't be readed
                                    // and would throw up expections all over us
                                }
                                if (klicGpu == null) continue;
                                if (Array.IndexOf(klicGpu.GetValueNames(), valueToFind) == -1)
                                {
                                    // the desired entry is not found, try the Settings subkey
                                    klicGpu = klicGpu.OpenSubKey("Settings", false);
                                    if (Array.IndexOf(klicGpu.GetValueNames(), valueToFind) != -1)
                                    {
                                        valueExists = true;
                                    }
                                }
                                else
                                {
                                    valueExists = true;
                                }

                                if (valueExists == true)
                                {
                                    // the value was found somewhere so in klicGpu we now have
                                    // the key which contains the desired value
                                    string reg_hodnota = klicGpu.GetValue(valueToFind).ToString();
                                    debugOutput("Parsing driver version from '" + reg_hodnota + "'", debug);
                                    if (reg_hodnota.Contains("."))
                                    {
                                        // check at least marginaly for correct format (trying to blind-fix bug #2)
                                        string[] hodnota = reg_hodnota.Split('.');
                                        debugOutput("Parsing driver version...", debug);
                                        long justFound = long.Parse(hodnota[0]) * 100 + long.Parse(hodnota[1]);
                                        // and seek for the highest possible value if there are more
                                        if (justFound > greatestFound) greatestFound = justFound;
                                    }
                                }
                            }
                        }
                        if (greatestFound == 0)
                        {
                            Console.WriteLine("Could not detect AMD Catalyst version.");
                            return false;
                        }
                        curVer = greatestFound;
                        break;
                }
            }
            return true;
        }

        public static bool versionDetectDLLs(List<string> dllToCheck)
        {
            // try to load every single DLL in the list and return false if any of them fails
            foreach (string dllko in dllToCheck)
            {
                IntPtr libPoint = LoadLibrary(dllko);
                if (libPoint == IntPtr.Zero)
                {
                    Console.WriteLine("Library " + dllko + " not found!");
                    return false;
                }
                FreeLibrary(libPoint);
                FreeLibrary(libPoint);
            }
            return true;
        }

        public static void selfUpdate()
        {
            // self updating procedure
            string myself = AppDomain.CurrentDomain.FriendlyName;
            if (myself == updateExe)
            {
                // if this is the NEW exe
                Console.WriteLine("Update in progress...");

                // delete the original one and overwrite it with myself
                waitForQuit(goodExe);
                File.Delete(goodExe);
                File.WriteAllBytes(goodExe, File.ReadAllBytes(myself));

                // start the original filename
                Process updater = new Process();
                updater.StartInfo.WorkingDirectory = installPath;
                if (os == 1)
                {
                    updater.StartInfo.FileName = "mono";
                    updater.StartInfo.Arguments = goodExe;
                }
                else
                {
                    updater.StartInfo.FileName = goodExe;
                }
                updater.StartInfo.Arguments += " " + String.Join(" ", arguments);

                updater.Start();
                Console.WriteLine("Update complete.");
                Environment.Exit(0);
            }
            else
            {
                // it is started regulary
                if (File.Exists(updateExe))
                {
                    // delete update exe if there was any - that means update was successful
                    waitForQuit(updateExe);
                    File.Delete(updateExe);
                }
                // calculate hash
                string hash = fileMD5(myself);
                byte[] responze = new byte[] { };
                try
                {
                    // upload it on server
                    responze = new WebClient().DownloadData(new Uri(webroot + "?a=update&hash=" + hash));
                }
                catch (WebException e)
                {
                    webError(e);
                    Environment.Exit(0);
                }
                if (responze.Length > 10240)
                {
                    Console.Write("New Hashtopus version available: ");
                    if (responze[0] == 77 && responze[1] == 90)
                    {
                        // if we got something in return its the new binary
                        Console.WriteLine("updating...");
                        Process updater = new Process();
                        if (os == 1)
                        {
                            // on unix, we can overwrite ourselves
                            File.WriteAllBytes(myself, responze);
                            updater.StartInfo.FileName = "mono";
                            updater.StartInfo.Arguments = myself;
                        }
                        else
                        {
                            // on windows, we must use transfer exe
                            File.WriteAllBytes(updateExe, responze);
                            updater.StartInfo.FileName = updateExe;
                        }
                        updater.StartInfo.Arguments += " " + String.Join(" ", arguments);
                        updater.StartInfo.WorkingDirectory = installPath;
                        updater.Start();
                        Environment.Exit(0);
                    }
                    else
                    {
                        Console.WriteLine("server problem!");
                    }
                }
            }
            
        }

        public static void waitForQuit(string procname)
        {
            // keep waiting 1 second until desired process exits
            Process[] bezi;
            do
            {
                Thread.Sleep(100);
                bezi = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(procname));
            } while (bezi.Length > 0);
        }

        public static string fileMD5(string fileName)
        {
            // calculate md5 checksum of a file
            MD5 hasher = MD5.Create();
            return BitConverter.ToString(hasher.ComputeHash(File.ReadAllBytes(fileName))).Replace("-", "").ToLower();
        }

        public static bool unpack7z(string szarchive, string outdir, string files = "")
        {
            string szexe = Path.Combine(installPath, "7zr");
            if (os == 0) szexe += ".exe";

            if (!File.Exists(szexe))
            {
                // download 7zip if needed
                Console.Write("Downloading 7zip...");
                if (!downloadFile(webroot + "?a=down&token=" + token + "&type=7zr", szexe)) return false;
                if (new FileInfo(szexe).Length < 102400)
                {
                    Console.WriteLine("Downloaded empty file.");
                    File.Delete(szexe);
                    return false;
                }
                if (os == 1)
                {
                    Process.Start("chmod", "+x \"" + szexe + "\"");
                }
            }
            
            // prepare launching process
            Process unpak = new Process();
            unpak.StartInfo.FileName = szexe;
            unpak.StartInfo.WorkingDirectory = installPath;
            unpak.StartInfo.Arguments = "x -y -o\"" + outdir + "\" \"" + szarchive + "\"";
            if (files != "") unpak.StartInfo.Arguments += " " + files;
            
            //unpak.StartInfo.UseShellExecute = false;
            Console.WriteLine("Extracting archive " + szarchive + "...");

            // unpack the archive
            debugOutput(unpak.StartInfo.FileName + " " + unpak.StartInfo.Arguments, debug);
            
            try
            {
                if (!unpak.Start()) return false;
            }
            catch
            {
                Console.WriteLine("Could not start 7zr.");
                return false;
            }
            unpak.WaitForExit();
            return true;
        }
        
        public static bool downloadHashcat()
        {
            // check if hashcat upgrading is needed and upgrade if yes
            string forceUpdate = "";
            if (!Directory.Exists(hcDir))
            {
                // the executable doesn't exist - tell the server we need to update
                // even we might be already marked as running the current version
                forceUpdate = "&force=1";
            }
            string[] responze;
            try
            {
                responze = new WebClient().DownloadString(webroot + "?a=down&token=" + token + "&type=hc" + forceUpdate + "&driver=" + curVer.ToString()).Split(separator);
            }
            catch (WebException e)
            {
                webError(e);
                return false;
            }
            switch (responze[0])
            {
                case "down_ok":
                    // there is an update available
                    Console.Write("New Hashcat version available, downloading...");

                    // download installation archive
                    string szarchive = Path.Combine(installPath, "hashcat.7z");
                    string url = responze[1];
                    if (File.Exists(szarchive)) File.Delete(szarchive);
                    if (!downloadFile(url, szarchive)) return false;

                    if (new FileInfo(szarchive).Length == 0)
                    {
                        Console.WriteLine("Downloaded empty file.");
                        File.Delete(szarchive);
                        return false;
                    }
                    string rootdir = Path.Combine(installPath, responze[3]);
                    cmdExecutable = responze[4];
                    
                    // cleanup whatever left from last time (should not be any, but just to be sure)
                    Console.WriteLine("Clearing directories...");
                    if (Directory.Exists(rootdir))
                    {
                        Console.WriteLine(rootdir);
                        Directory.Delete(rootdir, true);
                    }
                    if (Directory.Exists(hcDir))
                    {
                        Console.WriteLine(hcDir);
                        Directory.Delete(hcDir, true);
                    }
                    string extractFiles = responze[2];
                    List<string> extractFilesParse = new List<string>(extractFiles.Split(' '));
                    extractFilesParse.Add(cmdExecutable);

                    cmdExecutable = Path.Combine(hcDir, cmdExecutable);
                    
                    // find out what to extract where from what
                    string filesToExtract = "";
                    foreach (string extractFile in extractFilesParse)
                    {
                        filesToExtract += " " + "\"" + Path.Combine(responze[3], extractFile) + "\"";
                    }
                    // cut the loading space
                    filesToExtract = filesToExtract.Substring(1);
                    // call the extract function
                    if (!unpack7z(szarchive, installPath, filesToExtract)) break;
                    // delete the file, its not needed
                    File.Delete(szarchive);
                    // check if it worked
                    if (Directory.Exists(rootdir))
                    {
                        // rootdir was created correctly - rename it to the static name
                        Console.WriteLine("Renaming root directory...");
                        Directory.Move(rootdir, hcDir);
                    }
                    else
                    {
                        // expected rootdir was not unpacked
                        Console.WriteLine("Root directory was not unpacked or was incorrectly defined.");
                        return false;
                    }
                    if (Directory.Exists(rootdir) || !Directory.Exists(hcSubdir))
                    {
                        Console.WriteLine("Cannot prepare hashcat environment.");
                        return false;
                    }
                    // check if the operation was successful
                    if (!File.Exists(cmdExecutable))
                    {
                        if (Directory.Exists(hcDir)) Directory.Delete(hcDir, true);
                        Console.WriteLine("Executable for this platform was not delivered.");
                        return false;
                    }
                    else
                    {
                        if (os == 1) Process.Start("chmod", "+x \"" + cmdExecutable + "\"");
                    }

                    break;

                case "down_nok":
                    // server-side error
                    Console.WriteLine("Could not download hashcat: " + responze[1]);
                    return false;

                case "down_na":
                    // update required driver version
                    if (forceUpdate != "") return false;
                    cmdExecutable = Path.Combine(hcDir, responze[1]);
                    break;
            }
            return true;
        }

        public static void acceptEula()
        {
            // simply create a file with accepted eula
            string eulaFile = Path.Combine(hcDir, "eula.accepted");
            if (!File.Exists(eulaFile))
            {
                Console.WriteLine("Accepting EULA...");
                File.WriteAllText(eulaFile, "z\x00\x00\x00");
            }
        }

        public static int clearFinishedThreads()
        {
            threadList.RemoveAll(jeden => jeden.IsAlive == false);
            return threadList.Count;
        }

        public static void waitForThreads()
        {
            bool informed = false;
            while (true)
            {
                // delete all finished threads
                if (clearFinishedThreads() > 0)
                {
                    if (!informed)
                    {
                        Console.Write("Waiting for unfinished HTTP connections...");
                        informed = true;
                    }
                    Thread.Sleep(100);
                }
                else
                {
                    break;
                }
            }
            if (informed) Console.WriteLine("OK");
        }

        public static bool loadTask()
        {
            lock (uploadHashesLock)
            {
                if (!Directory.Exists(tasksDir))
                {
                    Console.Write("Creating tasks directory...");
                    Directory.CreateDirectory(tasksDir);
                    Console.WriteLine("OK");
                }

                Console.Write("Loading task...");
                // reset some values
                assignmentType = 0;
                cmdLine = "";
                zapIterator = 0;

                // load task info from server
                string[] responze = new string[] { };
                try
                {
                    responze = new WebClient().DownloadString(new Uri(webroot + "?a=task&token=" + token)).Split(separator);
                }
                catch (WebException e)
                {
                    webError(e);
                    return false;
                }
                switch (responze[0])
                {
                    case "task_ok":
                        task = responze[1];
                        hashList = responze[4];

                        // define hashlist
                        if (!Directory.Exists(hashlistDir)) Directory.CreateDirectory(hashlistDir);
                        hashListFile = Path.Combine(hashlistDir, hashList);

                        Console.WriteLine("assigned to " + task + ", hashlist " + hashList + " (" + responze[5] + ")");

                        // set internal vars for the task
                        zapDir = Path.Combine(hashlistDir, zapsSubdir + hashList);
                        assignmentType = int.Parse(responze[2]);

                        if (responze[5] == "new")
                        {
                            // the task is newly assigned, we will erase every possible previous work on this task
                            if (File.Exists(hashListFile)) File.Delete(hashListFile);
                        }

                        // load status interval
                        statusInterval = responze[6];

                        // now check the rest of the server message
                        if (responze.Length > 7)
                        {
                            // there are some files attached to this task
                            if (!Directory.Exists(filesDir)) Directory.CreateDirectory(filesDir);
                            for (int i = 7; i < responze.Length; i++)
                            {
                                string nam = responze[i];
                                string fnam = Path.Combine(filesDir, nam);

                                if (!File.Exists(fnam) || new FileInfo(fnam).Length == 0)
                                {
                                    // if the file doesn't exist, download it
                                    Console.WriteLine("Downloading file " + nam + "...");
                                    if (downloadFile(webroot + "?a=file&token=" + token + "&task=" + task + "&file=" + nam, fnam))
                                    {
                                        if (nam.ToLower().EndsWith(".7z"))
                                        {
                                            // unpack if it's 7zip archive
                                            if (unpack7z(fnam, filesDir))
                                            {
                                                // and save space by filling the original archive with short string
                                                File.WriteAllText(fnam, "UNPACKED");
                                            }
                                            else
                                            {
                                                return false;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        return false;
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("File " + nam + " already exists.");
                                }
                            }
                        }
                        // add paths to all existing files
                        string[] casti = responze[3].Split(' ');
                        for (int i = 0; i < casti.Length; i++)
                        {
                            string newcast = Path.Combine(filesDir, casti[i]);
                            if (File.Exists(newcast))
                            {
                                casti[i] = "\"" + newcast + "\"";
                            }
                        }
                        cmdLine = String.Join(" ", casti);

                        byte[] obsah;

                        // download hashlist as well
                        if (!File.Exists(hashListFile) || new FileInfo(hashListFile).Length == 0)
                        {
                            try
                            {
                                Console.Write("Downloading hashlist " + hashList + "...");
                                obsah = new WebClient().DownloadData(webroot + "?a=hashes&token=" + token + "&hashlist=" + hashList);
                            }

                            catch (WebException e)
                            {
                                webError(e);
                                return false;
                            }

                            Stream zpole = new MemoryStream(obsah);
                            StreamReader radky = new StreamReader(zpole);
                            // read first line of the result
                            string oneLine = radky.ReadLine();
                            if (oneLine == null)
                            {
                                Console.WriteLine("hashlist is empty!");
                                return false;
                            }
                            else
                            {
                                string[] obsah2 = oneLine.Split(separator);
                                switch (obsah2[0])
                                {
                                    case "hashes_nok":
                                        Console.WriteLine("failed: " + obsah2[1]);
                                        return false;

                                    case "hashes_na":
                                        Console.WriteLine("hashlist is fully cracked!");
                                        return false;

                                    default:
                                        // nothing of the above = we received raw hashlist. save it to file
                                        Console.WriteLine(obsah.Length.ToString() + " bytes");
                                        File.WriteAllBytes(hashListFile, obsah);
                                        break;
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("Hashlist already exists.");
                        }
                        // create command line and replace hashlistAlias with the real hashlist
                        cmdLine = cmdLine.Replace(hashlistAlias, "\"" + hashListFile + "\"");

                        return true;

                    case "task_nok":
                        Console.WriteLine("failed: " + responze[1]);
                        return false;

                    default:
                        Console.WriteLine("Task assignment returned nonsense.");
                        return false;
                }
            }
        }

        public static bool downloadFile(string remote, string local)
        {
            // launch async file downloading and report progress
            WebClient wcli = new WebClient();
            Uri adresa = new Uri(remote);
            ServicePoint wcsp = ServicePointManager.FindServicePoint(adresa);
            wcsp.Expect100Continue = false;

            // create the event handler
            wcli.DownloadProgressChanged += (sender, e) =>
            {
                lock (progressLock)
                {
                    // don't display the same number twice
                    int progres = e.ProgressPercentage;
                    if (progres != progresHelper)
                    {
                        if (progres % 10 == 0)
                        {
                            Console.Write(progres.ToString() + "% ");
                        }
                        progresHelper = progres;
                    }
                }
            };

            // download the file
            try
            {
                wcli.DownloadFileAsync(new Uri(remote), local);
            }
            catch (WebException e)
            {
                webError(e);
                return false;
            }
            while (wcli.IsBusy) Thread.Sleep(100);
            Console.WriteLine();
            return File.Exists(local);
        }

        public static void waitForIdle()
        {
            // wait assignmenType seconds until continuing

            eventhelper = false;
            if (eventmode)
            {
                if (File.Exists(idlefile)) File.Delete(idlefile);
                File.WriteAllText(readyfile, "Task " + task + " is ready to start cracking.");
                Console.Write("Waiting for external application to delete " + readyfile + " file...");
                while (File.Exists(readyfile))
                {
                    Thread.Sleep(100);
                }
                Console.WriteLine("OK.");
            }
            else
            {
                // TODO: implement proper idle check under unix systems
                if (os == 1) return;

                bool idleWarned = false;
                while (idleTime() < assignmentType)
                {
                    if (idleWarned == false)
                    {
                        Console.WriteLine("Waiting for the system to become idle for at least " + assignmentType.ToString() + "s");
                        idleWarned = true;
                    }
                    Thread.Sleep(1000);
                }
            }
        }

        public static uint idleTime()
        {
            // return how long the system has been idle by doing a kernel32 call
            uint idleTime = 0;
            // obviously, this works only on windows
            LASTINPUTINFO lastInputInfo = new LASTINPUTINFO();
            lastInputInfo.cbSize = (uint)Marshal.SizeOf(lastInputInfo);
            lastInputInfo.dwTime = 0;

            uint envTicks = (uint)Environment.TickCount;

            if (GetLastInputInfo(ref lastInputInfo))
            {
                uint lastInputTick = lastInputInfo.dwTime;
                idleTime = envTicks - lastInputTick;
            }

            return ((idleTime > 0) ? (idleTime / 1000) : 0);
        }

        public static uint loadTaskChunk()
        {
            // load a chunk of task the agent is assigned to
            Console.Write("Requesting chunk...");
            string[] responze = new string[] { };
            try
            {
                responze = new WebClient().DownloadString(new Uri(webroot + "?a=chunk&token=" + token + "&task=" + task)).Split(separator);
            }
            catch (WebException e)
            {
                webError(e);
                return 0;
            }
            switch (responze[0])
            {
                case "chunk_ok":
                    chunkId = responze[1];
                    chunkStart = responze[2];
                    chunkSize = responze[3];
                    Console.WriteLine("received " + chunkId + " (S: " + chunkStart + ", L:" + chunkSize + ")");
                    return 1;

                case "chunk_nok":
                    Console.WriteLine("failed: " + responze[1]);
                    return 0;

                case "bench_req":
                    benchTime = responze[1];
                    Console.WriteLine("benchmark required (" + benchTime + "s)");
                    return 2;

                case "keyspace_req":
                    Console.WriteLine("keyspace measuring required");
                    return 3;

                default:
                    Console.WriteLine("Chunk acquisition returned nonsense.");
                    return 0;
            }
        }

        public static string measureTaskKeyspace()
        {
            // server requested a benchmark, just run it and upload results
            Console.Write("Measuring keyspace...");
            ProcessStartInfo pinfo = new ProcessStartInfo();
            pinfo.FileName = cmdExecutable;
            pinfo.Arguments = cmdLine + " --session=hashtopus --keyspace --quiet";

            debugOutput(pinfo.FileName + " " + pinfo.Arguments, debug);
            
            
            // prepare the process
            pinfo.WorkingDirectory = tasksDir;
            pinfo.UseShellExecute = false;
            pinfo.RedirectStandardError = true;
            pinfo.RedirectStandardOutput = true;
            hashcatProcess = new Process();
            hashcatProcess.StartInfo = pinfo;
            hashcatProcess.ErrorDataReceived += (sender, argu) => outputError(argu.Data);
            // run it and capture output
            hashcatProcess.Start();
            hashcatProcess.BeginErrorReadLine();
            long ksHelper;
            string ksOutput = "";
            while (!hashcatProcess.HasExited)
            {
                // dig through the output
                while (!hashcatProcess.StandardOutput.EndOfStream)
                {
                    string vystup = hashcatProcess.StandardOutput.ReadLine();
                    debugOutput(vystup, debug);
                    if (long.TryParse(vystup, out ksHelper) && ksHelper > 0)
                    {
                        // grab the progress value and return it
                        ksOutput = vystup;
                        break;
                    }
                }
            }
            // check what we have gathered
            hashcatProcess.StandardOutput.Close();
            int code = hashcatProcess.ExitCode;
            if (code < 0 || code > 128)
            {
                string kod = code.ToString();
                errOutput.AppendLine("Hashcat (keyspace) exited with return code " + kod);
                ksOutput = "";
                Console.Write("ERROR " + kod);
            }
            else
            {
                Console.Write(ksOutput);
            }

            // upload errors that showed up (use the direct method)
            Console.WriteLine();
            uploadErrorsAsync();
            return ksOutput;
        }

        public static bool submitKeyspace(string keyspace)
        {
            // upload benchmark results to server
            Console.Write("Uploading keyspace size...");
            string[] responze = new string[] { };
            try
            {
                responze = new WebClient().DownloadString(new Uri(webroot + "?a=keyspace&token=" + token + "&task=" + task + "&keyspace=" + keyspace)).Split(separator);
            }
            catch (WebException e)
            {
                webError(e);
                return false;
            }
            switch (responze[0])
            {
                case "keyspace_ok":
                    Console.WriteLine("Accepted");
                    return true;

                case "keyspace_nok":
                    Console.WriteLine("Declined: " + responze[1]);
                    return false;

                default:
                    Console.WriteLine("Keyspace submission returned nonsense.");
                    return false;
            }
        }

        public static void benchTask()
        {
            // server requested a benchmark, just run it and upload results
            Console.Write("Benchmarking task for " + benchTime + "s...");
            ProcessStartInfo pinfo = new ProcessStartInfo();
            pinfo.FileName = cmdExecutable;
            pinfo.Arguments = cmdLine + " --runtime=" + benchTime + " --separator=" + separator + " --outfile=bench" + task + ".tmp --restore-disable --potfile-disable --status-automat --session=hashtopus";

            debugOutput(pinfo.FileName + " " + pinfo.Arguments, debug);
            
            
            // prepare process
            pinfo.WorkingDirectory = tasksDir;
            pinfo.UseShellExecute = false;
            pinfo.RedirectStandardError = true;
            pinfo.RedirectStandardOutput = true;
            hashcatProcess = new Process();
            hashcatProcess.StartInfo = pinfo;
            hashcatProcess.ErrorDataReceived += (sender, argu) => outputError(argu.Data);
            hashcatProcess.Start();
            hashcatProcess.BeginErrorReadLine();

            while (!hashcatProcess.HasExited)
            {
                // dig through the output
                while (!hashcatProcess.StandardOutput.EndOfStream)
                {
                    string vystup = hashcatProcess.StandardOutput.ReadLine();
                    debugOutput(vystup, debug);
                    if (vystup.Contains("STATUS\t"))
                    {
                        // grab the progress value and return it
                        parseStatus(vystup);
                        break;
                    }
                }
            }
            hashcatProcess.StandardOutput.Close();

            int code = hashcatProcess.ExitCode;
            if (code < 0 || code > 128)
            {
                string kod = code.ToString();
                errOutput.AppendLine("Hashcat (benchmark) exited with return code " + kod);
                Console.Write("ERROR " + kod);
            }
            else
            {
                Console.Write(chunkRProgress + "/" + chunkRSize);
            }

            // upload errors that showed up
            uploadErrorsAsync();

            // cleanup
            File.Delete(Path.Combine(tasksDir, "bench" + task + ".tmp"));

            Console.WriteLine();

        }


        public static bool submitBench()
        {
            // upload benchmark results to server
            Console.Write("Uploading benchmark result...");
            string[] responze = new string[] { };
            try
            {
                responze = new WebClient().DownloadString(new Uri(webroot + "?a=bench&token=" + token + "&task=" + task + "&progress=" + chunkRProgress + "&total=" + chunkRSize + "&state=" + chunkStatus)).Split(separator);
            }
            catch (WebException e)
            {
                webError(e);
                return false;
            }
            switch (responze[0])
            {
                case "bench_ok":
                    Console.WriteLine("Accepted (" + responze[1] + ")");
                    return true;

                case "bench_nok":
                    Console.WriteLine("Declined: " + responze[1]);
                    return false;

                default:
                    Console.WriteLine("Benchmark submission returned nonsense.");
                    return false;
            }
        }

        public static bool startHashcat()
        {
            // simply create hashcat process in the correct directories

            // also create directory for zaps, should it not exist
            if (Directory.Exists(zapDir))
            {
                Console.WriteLine("Cleaning zap directory...");
                Directory.Delete(zapDir, true);
            }
            else
            {
                Console.WriteLine("Creating zap directory...");
            }
            Directory.CreateDirectory(zapDir);

            ProcessStartInfo pinfo = new ProcessStartInfo();
            pinfo.FileName = cmdExecutable;
            // construct the command line from parameters
            pinfo.Arguments = cmdLine + " --potfile-disable --quiet --restore-disable --session=hashtopus --status --status-automat --status-timer=" + statusInterval + " --outfile-check-dir=\"" + zapDir + "\" --outfile-check-timer=" + statusInterval + " --remove --remove-timer=" + statusInterval + " --separator=" + separator + " --skip=" + chunkStart + " --limit=" + chunkSize;

            debugOutput(pinfo.FileName + " " + pinfo.Arguments, debug);
            
            
            pinfo.WorkingDirectory = tasksDir;
            pinfo.UseShellExecute = false;
            pinfo.RedirectStandardError = true;
            pinfo.RedirectStandardOutput = true;

            hashcatProcess = new Process();
            hashcatProcess.StartInfo = pinfo;
            // create event handlers for normal and error output
            hashcatProcess.OutputDataReceived += (sender, argu) => outputNormal(argu.Data);
            hashcatProcess.ErrorDataReceived += (sender, argu) => outputError(argu.Data);
            hashcatProcess.EnableRaisingEvents = true;
            bool novy = hashcatProcess.Start();
            hashcatProcess.BeginOutputReadLine();
            hashcatProcess.BeginErrorReadLine();
            return novy;
        }

        public static void outputNormal(string co)
        {
            // callback for stdout
            if (co != null) {
                debugOutput(co, debug);
                int poz = co.LastIndexOf(separator);
                if (poz == -1)
                {
                    // there are no separators, its status update
                    co = co.Trim();
                    if (co != "")
                    {
                        if (co.Contains("STATUS\t"))
                        {
                            // its a progress, parse the line and get data
                            parseStatus(co);

                            // upload errors
                            uploadErrors();

                            // upload hashes only if nothing is being uploaded right now
                            // or we are ending a chunk
                            if (int.Parse(chunkStatus) >= 4 || clearFinishedThreads() == 0)
                            {
                                uploadHashes();
                            }
                        }
                    }
                }
                else
                {
                    // there is separator - it's cracking output
                    lock (crackedLock)
                    {
                        crackedHashes.AppendLine(co);
                    }
                }

            }
        }

        public static void parseStatus(string line)
        {
            string[] items = line.Split('\t');
            int i = 0;
            // parse status
            if (items[i] == "STATUS")
            {
                chunkStatus = items[1];
                i += 2;
            }
            else
            {
                return;
            }

            // parse speed
            if (items[i] == "SPEED")
            {
                i = 3;
                decimal speed = 0;
                do
                {
                    decimal keys = decimal.Parse(items[i], CultureInfo.InvariantCulture);
                    decimal duration = decimal.Parse(items[i + 1], CultureInfo.InvariantCulture);
                    if (duration > 0) speed += (keys / duration) * 1000;
                    i += 2;
                } while (items[i] != "CURKU");
                totalSpeed = Math.Round(speed).ToString();
            }
            // parse checkpoint
            if (items[i] == "CURKU")
            {
                chunkCurKUlast = chunkCurKU;
                chunkCurKU = items[i + 1];
                i += 2;
            }
            // parse keyspace progress
            if (items[i] == "PROGRESS")
            {
                chunkRProgress = items[i + 1];
                chunkRSize = items[i + 2];
                i += 3;
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
                    debugOutput(co, true, ConsoleColor.Red);
                    errOutput.AppendLine(co);
                }
            }
        }

        public static void uploadHashes()
        {
            // start the upload process in a new thread
            ThreadStart ts = new ThreadStart(uploadHashesAsync);
            Thread thr = new Thread(ts);
            threadList.Add(thr);
            thr.Start();
        }
        
        public static void uploadHashesAsync()
        {
            lock (uploadHashesLock)
            {
                // cache data structure
                string hashesToUpload;
                lock (crackedLock)
                {
                    hashesToUpload = crackedHashes.ToString();
                    crackedHashes = new StringBuilder();
                }

                // define new webrequest
                HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(webroot + "?a=solve&token=" + token + "&chunk=" + chunkId + "&curku=" + chunkCurKU + "&speed=" + totalSpeed + "&progress=" + chunkRProgress + "&total=" + chunkRSize + "&state=" + chunkStatus);
                wr.Method = "POST";
                wr.Timeout = int.MaxValue;
                wr.ServicePoint.Expect100Continue = false;
                byte[] erej = Encoding.ASCII.GetBytes(hashesToUpload);

                // print the progress in color if we have just hit checkpoint
                if (chunkCurKU != chunkCurKUlast) Console.ForegroundColor = ConsoleColor.Cyan;
                string progre = "[" + chunkRProgress + "/" + chunkRSize + "]";
                Console.ResetColor();

                Console.Write(progre + " Uploading " + erej.Length.ToString() + " b");

                // write data to the stream
                StreamReader radky = null;
                try
                {
                    Stream wrStream = wr.GetRequestStream();
                    wrStream.Write(erej, 0, erej.Length);
                    wrStream.Close();
                    Console.Write(".");

                    // read the response
                    HttpWebResponse wrs = (HttpWebResponse)wr.GetResponse();
                    Console.Write(".");

                    if (wrs.StatusCode != HttpStatusCode.OK)
                    {
                        Console.WriteLine("ERROR " + wrs.StatusDescription);
                        return;
                    }

                    // read the data inside the response
                    Stream wrsStream = wrs.GetResponseStream();
                    radky = new StreamReader(wrsStream);
                    Console.Write(".");
                }

                catch (WebException e)
                {
                    webError(e);
                    // put back the hashes so they will be uploaded next time
                    if (hashesToUpload.Length > 0)
                    {
                        crackedHashes.Append(hashesToUpload);
                    }
                    return;
                }

                long solved = 0, zapped = 0;
                if (!radky.EndOfStream)
                {
                    // read first line and parse it
                    string oneLine = radky.ReadLine();
                    string[] responze = oneLine.Split(separator);

                    switch (responze[0])
                    {
                        case "solve_ok":
                            // save how many hashes the server marked as cracked
                            solved = long.Parse(responze[1]);
                            if (solved > 0) Console.ForegroundColor = ConsoleColor.Green;
                            Console.Write("Cracked " + responze[1]);
                            Console.ResetColor();
                            long skipped = long.Parse(responze[2]);
                            if (skipped > 0)
                            {
                                Console.Write(", ");
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.Write("skipped " + responze[2]);
                                Console.ResetColor();
                            }
                            break;

                        case "solve_nok":
                            Console.WriteLine("ERROR: " + responze[1]);
                            // terminate the hashcat process to prevent wasted work
                            if (!hashcatProcess.HasExited) hashcatProcess.Kill();
                            break;

                        default:
                            Console.WriteLine("HTTP >> " + oneLine);
                            break;
                    }

                    if (responze.Length >= 4)
                    {
                        // if the message goes on
                        if (responze[3] == "zap_ok")
                        {
                            // following are the zaps
                            Console.Write(", ");
                            Console.ForegroundColor = ConsoleColor.Blue;
                            Console.Write("zapped ");
                            // create a new file
                            string tmpFile = Path.Combine(tasksDir, "zaps.tmp");

                            // create a temp file outside scanned directory
                            StreamWriter saveZaps = new StreamWriter(tmpFile);
                            zapIterator++;
                            while (true)
                            {
                                // keep reading non empty lines
                                oneLine = radky.ReadLine();
                                if (oneLine == null) break;
                                // write the zap
                                zapped++;
                                saveZaps.WriteLine(oneLine + separator);
                            }
                            // close the file
                            saveZaps.Close();
                            // move the file to scanned directory
                            string finalFile = Path.Combine(zapDir, "zaps" + zapIterator.ToString() + ".txt");
                            File.Move(tmpFile, finalFile);
                            // return how many zaps were written
                            Console.Write(zapped.ToString() + "/" + responze[4]);
                            Console.ResetColor();
                        }

                        if (responze[3] == "stop")
                        {
                            // the hashlist was fully cracked, no need to continue working
                            Console.Write(", ");
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.Write("hashlist cracked!");
                            Console.ResetColor();
                            zapped++;
                            if (!hashcatProcess.HasExited) hashcatProcess.Kill();
                        }

                    }
                }
                // let the response stream rest in peace
                radky.Close();

                // write a star if something was done
                if (solved + zapped > 0)
                {
                    Console.Write(" ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write("[*]");
                    Console.ResetColor();
                }
                Console.WriteLine();
            }
        }

        public static void uploadErrors()
        {
            if (errOutput.Length == 0) return;
            // start the upload process in a new thread
            ThreadStart ts = new ThreadStart(uploadErrorsAsync);
            Thread thr = new Thread(ts);
            threadList.Add(thr);
            thr.Start();
        }
        
        public static void uploadErrorsAsync()
        {
            if (errOutput.Length == 0) return;
            
            // cycle error data structures
            string errorsToUpload = errOutput.ToString();
            errOutput = new StringBuilder();

            // define new webrequest
            HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(webroot + "?a=err&token=" + token + "&task=" + task);
            wr.Method = "POST";
            wr.ServicePoint.Expect100Continue = false;
            byte[] erej = Encoding.ASCII.GetBytes(errorsToUpload);

            // write data to the stream
            Console.Write("[ERR] Uploading " + erej.Length.ToString() + " b...");
            Stream wrStream = wr.GetRequestStream();
            wrStream.Write(erej, 0, erej.Length);
            wrStream.Close();

            // read the response
            HttpWebResponse wrs = (HttpWebResponse)wr.GetResponse();

            if (wrs.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine("ERROR " + wrs.StatusDescription);
                return;
            }

            // read the data inside the response
            Stream wrsStream = wrs.GetResponseStream();
            StreamReader radky = new StreamReader(wrsStream);

            // read first line and parse it
            string oneLine = radky.ReadToEnd();
            string[] responze = oneLine.Split(separator);

            switch (responze[0])
            {
                case "err_ok":
                    Console.WriteLine("Uploaded " + responze[1] + " errors");
                    break;

                case "err_nok":
                    Console.WriteLine("ERROR: " + responze[1]);
                    break;

                default:
                    Console.WriteLine("HTTP >> " + oneLine);
                    break;
            }
            // let the response stream rest in peace
            radky.Close();
        }
    }
}

