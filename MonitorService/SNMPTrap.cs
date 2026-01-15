using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.ServiceProcess;
using System.Text;

namespace MonitorService
{
    public class SNMPTrap : ServiceBase
    {
        private UdpClient udpClient;
        private IPEndPoint remoteEndPoint;
        private bool isRunning = false;
        string outputFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "snmp_data.txt");
        string community = "public";
        int port = 162;

        internal SNMPTrap()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.ServiceName = "MonitorService";
        }

        protected override void OnStart(string[] args)
        {
            StartListening();
        }

        protected override void OnStop()
        {
            StopListening();
        }

        public void StartListening()
        {
            if (isRunning) return;

            isRunning = true;
            udpClient = new UdpClient(port);
            remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            udpClient.BeginReceive(ReceivedCallback, null);
        }

        public void StopListening()
        {
            isRunning = false;
            udpClient?.Close();
        }

        private void ReceivedCallback(IAsyncResult ar)
        {
            if (!isRunning) return;

            try
            {
                byte[] receivedData = udpClient.EndReceive(ar, ref remoteEndPoint);
                string snmpLogEntry = ProcessSnmpPacket(receivedData, remoteEndPoint);
                File.AppendAllText(outputFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {snmpLogEntry}\n");
                udpClient.BeginReceive(ReceivedCallback, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error receiving data: {ex.Message}");
            }
        }

        static string ProcessSnmpPacket(byte[] data, IPEndPoint remoteEndPoint)
        {
            StringBuilder result = new StringBuilder();
            result.Append($"From: {remoteEndPoint.Address}:{remoteEndPoint.Port} ");
            string hexData = BitConverter.ToString(data).Replace("-", " ");
            result.Append($"| Full Hex: {hexData} (Length: {data.Length} bytes)");
            return result.ToString();
        }

        // Public methods for debugging
        public void StartDebug()
        {
            StartListening();
            Console.WriteLine("Listener started in debug mode");
        }

        public void StopDebug()
        {
            StopListening();
            Console.WriteLine("Listener stopped in debug mode");
        }
    }
}
