using System;
using System.ServiceProcess;

namespace MonitorService
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "/debug")
                RunAsConsole();
            else
                ServiceBase.Run(new ServiceBase[] { new SNMPTrap() });
        }

        private static void RunAsConsole()
        {
            var snmptrap = new SNMPTrap();
            snmptrap.StartDebug();
            Console.WriteLine("Service is running. Press any key to stop...");

            try { Console.ReadKey(true); }
            finally { snmptrap.StopDebug(); }
        }
    }
}
