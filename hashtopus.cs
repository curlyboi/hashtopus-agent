using System;
using System.Threading;
using System.ServiceProcess;
using System.ComponentModel;


namespace hashtopus
{
    class Hashtopus
    {
        public const string ServiceName = "Hashtopus";
        public static BackgroundWorker bw = new BackgroundWorker();
        public static AutoResetEvent rst = new AutoResetEvent(false);

        public class Service : ServiceBase
        {
            public Service()
            {
                ServiceName = Hashtopus.ServiceName;
            }

            protected override void OnStart(string[] args)
            {
                Hashtopus.Start(args);
            }

            protected override void OnStop()
            {
                Hashtopus.Stop();
            }
        }


        private static void Start(string[] args)
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
            rst.WaitOne();
        }

        private static void Stop()
        {
            bw.CancelAsync();
        }

        static void Main(string[] args)
        {
            if (!Environment.UserInteractive)
            {
                // running as service
                Htp.srvRun = true;
                ServiceBase.Run(new Service());
            }
            else
            {
                // running as console app
                Start(args);
            }
        }

    }
}

