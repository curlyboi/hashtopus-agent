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
using System.Globalization;
using System.IO.Compression;

namespace hashtopus
{
    class hashtopus
    {

        public static bool eventmode = false;
        public static string readyfile = "event_ready";
        public static string idlefile = "event_idle";
        public static bool eventhelper = false;

        static void Main(string[] args)
        {
            // switch to executable directory
            Dirs.SetDir();
            
            Console.Title = "Hashtopus " + Htp.ver;
            Console.WriteLine(Console.Title);
            
            //     Console.WriteLine("Debug mode on.");
            //    Debug.flag = true;

            //if (Array.IndexOf(arguments, "eventmode") > -1) eventmode = true;

            // ENTRY POINT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

            // read the executable for connector URL
            if (!Htp.detectUrl())
            {
                Console.WriteLine("No URL found in this executable. Please deploy agent from administration.");
                return;
            }

            // find out system internal details
            Htp.detectAll();

            // MAIN CYCLE START
            do
            {
                // wait for unfinished requests from last cycle
                Threads.WaitForFinish();

                // self update hashtopus
                if (Htp.SelfUpdate())
                {
                    return;
                }

                // login to the server
                while (!Agent.Login())
                {
                    // on fail, register and try again
                    if (!Agent.Register())
                        Htp.WaitForIt();
                }

                // update hashcat if needed
                while (!Hashcat.Update())
                {
                    // repeat if it failed
                    Htp.WaitForIt();
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
                                } else
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
                    if (!eventhelper)
                    {
                        eventhelper = true;
                        Console.WriteLine("Waiting for next assignment...");
                        if (eventmode)
                        {
                            File.WriteAllText(idlefile, "No more work to do.");
                        }
                    }
                    Htp.WaitForIt();
                }
                // repeat indefinitely
            } while (true);
        }

    }
}

