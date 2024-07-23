using System;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
 
class Program
{
    const int AF_INET = 2;
    const int TCP_TABLE_OWNER_PID_ALL = 5;
    const string BASE_URL = "https://www.virustotal.com/vtapi/v2/ip-address/report";
    const string API_KEY = " ";
 
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }
 
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public MIB_TCPROW_OWNER_PID[] table;
    }
 
    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern int GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int TableClass,
        int Reserved
    );
 
    static async Task Main(string[] args)
    {
        DisplayBanner();
        DisplayMenu();
 
        string choice = Console.ReadLine();
 
        switch (choice)
        {
            case "1":
                ListActiveConnections();
                break;
            case "2":
                await CheckIp();
                break;
            default:
                Console.WriteLine("Ungültige Auswahl.");
                break;
        }
    }
 
    static void DisplayBanner()
    {
        Console.WriteLine(" ____  ____      ____  _____  _____  __   ");
        Console.WriteLine("(_  _)(  _ \\ ___(_  _)(  _  )(  _  )(  )  ");
        Console.WriteLine(" _)(_  )___/(___) )(   )(_)(  )(_)(  )(__ ");
        Console.WriteLine("(____)(__)       (__) (_____)(_____)(____)");
        Console.WriteLine("            N3LL4 v.1");
        Console.WriteLine();
    }
 
    static void DisplayMenu()
    {
        Console.WriteLine("Willkommen! Was willst du tun?");
        Console.WriteLine("[1] Auflisten aktiver Netzwerkverbindungen");
        Console.WriteLine("[2] IP überprüfen");
        Console.Write("Gebe die Nummer ein: ");
    }
 
    static void ListActiveConnections()
    {
        try
        {
            int bufferSize = 0;
            IntPtr tcpTable = IntPtr.Zero;
 
            GetExtendedTcpTable(tcpTable, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            tcpTable = Marshal.AllocHGlobal(bufferSize);
 
            if (GetExtendedTcpTable(tcpTable, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0)
            {
                IntPtr currentRowPtr = tcpTable;
                int numEntries = Marshal.ReadInt32(currentRowPtr);
                currentRowPtr = (IntPtr)((long)currentRowPtr + Marshal.SizeOf(typeof(uint)));
 
                for (int i = 0; i < numEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID tcpRow = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(currentRowPtr);
 
                    string localAddress = new IPAddress(tcpRow.localAddr).ToString();
                    string remoteAddress = new IPAddress(tcpRow.remoteAddr).ToString();
                    int localPort = ntohs((ushort)tcpRow.localPort);
                    int remotePort = ntohs((ushort)tcpRow.remotePort);
 
                    Console.WriteLine($"Local Address: {localAddress}:{localPort} - Remote Address: {remoteAddress}:{remotePort} - PID: {tcpRow.owningPid}");
 
                    currentRowPtr = (IntPtr)((long)currentRowPtr + Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID)));
                }
            }
 
            Marshal.FreeHGlobal(tcpTable);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ein Fehler ist aufgetreten: {ex.Message}");
        }
    }
 
    static async Task CheckIp()
    {
        try
        {
            Console.Write("Bitte geben Sie die zu überprüfende IP-Adresse ein: ");
            string ip = Console.ReadLine();
 
            if (IPAddress.TryParse(ip, out IPAddress address))
            {
                bool isMalicious = await CheckIpWithVirusTotal(ip);
                Console.WriteLine($"Is Malicious: {isMalicious}");
            }
            else
            {
                Console.WriteLine("Ungültige IP-Adresse eingegeben.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ein Fehler ist aufgetreten: {ex.Message}");
        }
    }
 
    static async Task<bool> CheckIpWithVirusTotal(string ip)
    {
        using (HttpClient client = new HttpClient())
        {
            try
            {
                string url = $"{BASE_URL}?apikey={API_KEY}&ip={ip}";
 
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();
 
                string responseBody = await response.Content.ReadAsStringAsync();
                return !responseBody.Contains("\"positives\":0");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine($"Anfragefehler: {e.Message}");
                return false;
            }
        }
    }
 
    static ushort ntohs(ushort netshort)
    {
        return (ushort)(((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8));
    }
}
