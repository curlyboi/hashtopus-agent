using System;
using System.Threading;
using System.ServiceProcess;
using System.ComponentModel;


namespace hashtopus
{
    class Hashtopus
    {
        public const string ServiceName = "Hashtopus";

        public class Service : ServiceBase
        {
            public Service()
            {
                ServiceName = Hashtopus.ServiceName;
            }

            protected override void OnStart(string[] args)
            {
                HtpService.Start(args);
            }

            protected override void OnStop()
            {
                GlobObj.OutL("Hashtopus service was stopped.");
                HtpService.Stop();
            }
        }


        
        static void Main(string[] args)
        {
            if (Environment.UserInteractive || Environment.OSVersion.Platform == PlatformID.Unix)
            {
                // start thread directly
                HtpService.Start(args);
                // and wait for finish before closing console
                HtpService.rst.WaitOne();
            }
            else
            {
                // running as service
                HtpService.enabled = true;
                ServiceBase.Run(new Service());
            }
        }

    }
}

