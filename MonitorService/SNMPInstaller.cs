using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace MonitorService
{
    [RunInstaller(true)]
    public class SNMPInstaller : Installer
    {
        private ServiceProcessInstaller serviceProcessInstaller;
        private ServiceInstaller serviceInstaller;

        public SNMPInstaller()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.serviceProcessInstaller = new ServiceProcessInstaller();
            this.serviceInstaller = new ServiceInstaller();
            this.serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            this.serviceProcessInstaller.Password = null;
            this.serviceProcessInstaller.Username = null;
            this.serviceInstaller.ServiceName = "MonitorService";
            this.serviceInstaller.DisplayName = "Monitor Service";
            this.serviceInstaller.Description = "Captures SNMP data in SQL and runs a website to view the data in SQL. Website also gives the option to view disk space of added servers.";
            this.serviceInstaller.StartType = ServiceStartMode.Automatic;
            this.Installers.AddRange(new Installer[]
            {
                this.serviceProcessInstaller,
                this.serviceInstaller
            });
        }
    }
}
