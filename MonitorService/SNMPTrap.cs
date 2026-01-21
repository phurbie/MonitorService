using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;

namespace MonitorService
{
    public class SNMPTrap : ServiceBase
    {
        private UdpClient udpClient;
        private IPEndPoint remoteEndPoint;
        private bool isRunning = false;
        int port = 162;
        private readonly SQLStorage _sqlStorage;
        private WebServer _webServer;

        internal SNMPTrap()
        {
            InitializeComponent();
            _sqlStorage = new SQLStorage();
        }

        private void InitializeComponent()
        {
            this.ServiceName = "MonitorService";
            _webServer = new WebServer();
        }

        protected override void OnStart(string[] args)
        {
            _sqlStorage.InitializeDatabase();
            _webServer.Start();
            StartListening();
        }

        protected override void OnStop()
        {
            _webServer.Stop();
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
                ProcessSnmpPacket(receivedData, remoteEndPoint);
                udpClient.BeginReceive(ReceivedCallback, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error receiving data: {ex.Message}");
            }
        }

        private void ProcessSnmpPacket(byte[] data, IPEndPoint remoteEndPoint)
        {
            try
            {
                int offset = 0;

                string errorInfo = "";
                if (data[offset++] != 0x30) errorInfo += $"Expected 0x30 at offset 0, got {data[0]:X2}; ";
                int totalLength = DecodeBerLength(data, ref offset);
                if (offset + totalLength > data.Length) errorInfo += $"Invalid total length: {totalLength} at offset {offset}; ";

                string snmpVersion = "";
                if (data[offset++] != 0x02) errorInfo += $"Missing version marker 0x02, got {data[offset - 1]:X2}; ";

                int versionLength = DecodeBerLength(data, ref offset);
                int version = 0;
                for (int i = 0; i < versionLength; i++) version = (version << 8) | data[offset++];
                snmpVersion = $"SNMPv{version + 1}";

                string community = "";
                if (data[offset++] != 0x04) errorInfo += $"Missing community marker 0x04, got {data[offset - 1]:X2}; ";
                int communityLength = DecodeBerLength(data, ref offset);
                community = Encoding.ASCII.GetString(data, offset, communityLength);
                offset += communityLength;

                string pdu = "";
                byte pduTag = data[offset];
                if (pduTag != 0xA7 && pduTag != 0xA4) errorInfo += $"Unsupported PDU tag 0x{pduTag:X2}";
                offset++;
                int pduLength = DecodeBerLength(data, ref offset);
                pdu = (pduTag == 0xA7) ? "TrapV2" : "TrapV1";

                string request = "";
                long requestId = 0;
                int errorStatus = 0;
                int errorIndex = 0;
                if (pduTag == 0xA7)
                {
                    if (data[offset++] != 0x02) errorInfo += $"Expected request-id INTEGER";
                    int len = DecodeBerLength(data, ref offset);
                    requestId = 0;
                    for (int i = 0; i < len; i++) requestId = (requestId << 8) | data[offset++];
                    request += ($"RequestID: {requestId} ");

                    if (data[offset++] != 0x02) errorInfo += "Expected error-status INTEGER";
                    len = DecodeBerLength(data, ref offset);
                    errorStatus = 0;
                    for (int i = 0; i < len; i++) errorStatus = (errorStatus << 8) | data[offset++];
                    if (data[offset++] != 0x02) throw new Exception("Expected error-index INTEGER");
                    len = DecodeBerLength(data, ref offset);
                    errorIndex = 0;
                    for (int i = 0; i < len; i++) errorIndex = (errorIndex << 8) | data[offset++];

                    if (errorStatus != 0 || errorIndex != 0) errorInfo += $"Error: {errorStatus}/{errorIndex} ";
                }

                else if (pduTag == 0xA4)
                {
                    if (data[offset++] != 0x06) errorInfo += "Missing enterprise OID";
                    int entLen = DecodeBerLength(data, ref offset);
                    string enterprise = DecodeOid(data, offset, entLen);
                    offset += entLen;
                    request += $"Enterprise: {enterprise} ";

                    if (data[offset++] != 0x40) errorInfo += "Missing agent address";
                    int addrLen = DecodeBerLength(data, ref offset);
                    string agentAddr = (addrLen == 4) ? $"{data[offset]}.{data[offset + 1]}.{data[offset + 2]}.{data[offset + 3]}" : "[Invalid]";
                    offset += addrLen;
                    request += $"AgentAddr: {agentAddr} ";

                    if (data[offset++] != 0x02) errorInfo += "Missing generic trap";
                    int genLen = DecodeBerLength(data, ref offset);
                    int genericTrap = 0;
                    for (int i = 0; i < genLen; i++) genericTrap = (genericTrap << 8) | data[offset++];
                    request += $"Generic: {genericTrap} ";

                    if (data[offset++] != 0x02) errorInfo += ("Missing specific trap");
                    int specLen = DecodeBerLength(data, ref offset);
                    int specificTrap = 0;
                    for (int i = 0; i < specLen; i++) specificTrap = (specificTrap << 8) | data[offset++];
                    request += $"Specific: {specificTrap} ";

                    if (data[offset++] != 0x43) errorInfo += ("Missing timestamp");
                    int tsLen = DecodeBerLength(data, ref offset);
                    uint timestamp = 0;
                    for (int i = 0; i < tsLen; i++) timestamp = (timestamp << 8) | data[offset++];
                    request += $"Timestamp: {timestamp} ";
                }

                string varBind = "";
                if (data[offset++] != 0x30) errorInfo += ("Missing VarBindList");
                int varBindListLength = DecodeBerLength(data, ref offset);
                int varBindEnd = offset + varBindListLength;
                bool firstVarBind = true;
                while (offset < varBindEnd)
                {
                    if (!firstVarBind) varBind += " | ";
                    firstVarBind = false;

                    if (data[offset++] != 0x30) errorInfo += "Invalid VarBind";
                    int varBindLength = DecodeBerLength(data, ref offset);

                    if (data[offset++] != 0x06) errorInfo += ("Missing OID");
                    int oidLength = DecodeBerLength(data, ref offset);
                    string oid = DecodeOid(data, offset, oidLength);
                    offset += oidLength;

                    byte valueTag = data[offset++];
                    int valueLength = DecodeBerLength(data, ref offset);
                    string valueStr = DecodeValue(data, offset, valueLength, valueTag);
                    offset += valueLength;

                    string friendlyOid;
                    switch (oid)
                    {
                        case "1.3.6.1.4.1.3183.1.1.1":
                            friendlyOid = "PET Event Data (binary)";
                            break;
                        case "1.3.6.1.4.1.3183.1.1.2":
                            friendlyOid = "Event Type/Severity";
                            break;
                        case "1.3.6.1.4.1.3183.1.1.3":
                            friendlyOid = "Event Source";
                            break;
                        case "1.3.6.1.4.1.3183.1.1.4":
                            friendlyOid = "System Serial Number";
                            break;
                        case "1.3.6.1.4.1.3183.1.1.5":
                            friendlyOid = "Product Code";
                            break;
                        case "1.3.6.1.4.1.3183.1.1.6":
                            friendlyOid = "Event Message";
                            break;
                        default:
                            friendlyOid = oid;
                            break;
                    }

                    varBind += $"{friendlyOid} = {valueStr}";
                }

                string hexData = BitConverter.ToString(data).Replace("-", " ");
                _sqlStorage.StoreSNMPData(DateTime.Now, remoteEndPoint.Address.ToString(), remoteEndPoint.Port, errorInfo, snmpVersion, community, pdu, request, varBind, hexData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing SNMP packet: {ex.Message}");
                string hexData = BitConverter.ToString(data).Replace("-", " ");
                _sqlStorage.StoreSNMPData(DateTime.Now, remoteEndPoint.Address.ToString(), remoteEndPoint.Port, $"Parsing failed: {ex.Message}", "", "", "", "", "", hexData);
            }
        }

        private static int DecodeBerLength(byte[] data, ref int offset)
        {
            byte first = data[offset++];
            if ((first & 0x80) == 0) return first;
            int lenBytes = first & 0x7F;
            if (lenBytes > 4) throw new Exception("Length too long");
            int length = 0;
            for (int i = 0; i < lenBytes; i++)
                length = (length << 8) | data[offset++];
            return length;
        }

        private static string DecodeOid(byte[] data, int offset, int length)
        {
            StringBuilder sb = new StringBuilder();
            long subId = 0;
            bool isFirst = true;

            for (int i = 0; i < length; i++)
            {
                byte b = data[offset++];
                subId = (subId << 7) | ((uint)b & 0x7F);

                if ((b & 0x80) == 0)
                {
                    if (isFirst)
                    {
                        isFirst = false;
                        if (subId < 40) sb.Append("0." + subId);
                        else if (subId < 80) sb.Append("1." + (subId - 40));
                        else sb.Append("2." + (subId - 80));
                    }
                    else
                    {
                        sb.Append("." + subId);
                    }
                    subId = 0;
                }
            }
            return sb.ToString();
        }

        private static string DecodeValue(byte[] data, int offset, int length, byte tag)
        {
            switch (tag)
            {
                case 0x02:
                    long iVal = (length > 0 && (data[offset] & 0x80) != 0) ? -1L : 0L;
                    for (int i = 0; i < length; i++) iVal = (iVal << 8) | data[offset++];
                    return iVal.ToString();
                case 0x04:
                    string str = Encoding.ASCII.GetString(data, offset, length);
                    return Printable(str) ? $"\"{str}\"" : BitConverter.ToString(data, offset, length).Replace("-", " ");
                case 0x05:
                    return "NULL";
                case 0x06:
                    return DecodeOid(data, offset, length);
                case 0x40:
                    if (length == 4) return $"{data[offset]}.{data[offset + 1]}.{data[offset + 2]}.{data[offset + 3]}";
                    return BitConverter.ToString(data, offset, length).Replace("-", " ");
                case 0x41:
                case 0x42:
                case 0x46:
                    uint uVal = 0;
                    for (int i = 0; i < length; i++) uVal = (uVal << 8) | data[offset++];
                    return uVal.ToString();
                case 0x43:
                    uint tt = 0;
                    for (int i = 0; i < length; i++) tt = (tt << 8) | data[offset++];
                    return $"TimeTicks({tt})";
                default:
                    return $"[Tag 0x{tag:X2}: {BitConverter.ToString(data, offset, length).Replace("-", " ")}]";
            }
        }

        private static bool Printable(string s) => s.All(c => c >= 32 && c <= 126);

        public void StartDebug()
        {
            _sqlStorage.InitializeDatabase();
            _webServer.Start();
            StartListening();
            Console.WriteLine("Listener started in debug mode");
        }

        public void StopDebug()
        {
            _webServer.Stop();
            StopListening();
            Console.WriteLine("Listener stopped in debug mode");
        }
    }
}
