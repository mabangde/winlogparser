using System;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Collections;
using System.Globalization;
using System.Collections.Generic;
using winlogparser;
using System.Text;
using System.Linq;

namespace winlogparser
{
    public class LoginLog
    {
        public string IpAddress { get; set; }
        public DateTime SystemTime { get; set; }
        // 你可以添加其他的属性，比如 EventRecordID, TargetDomainName, TargetUserName, EventID, LogonType
    }
    class winlogParser
    {
        static Hashtable logtypename = new Hashtable(){
            {2, "type = 2|Interactive|交互式登录"},
            {3, "type = 3|Network|网络登录"},
            {4, "type = 4|Batch|批处理登录"},
            {5, "type = 5|Service|服务登录"},
            {7, "type = 7|Unlock|解锁登录"},
            {8, "type = 8|NetworkCleartext|网络明文方式登录"},
            {10, "type = 10|Remotelnteractive|远程桌面方式登录"},
            {11, "type = 11|CachedUnlock|缓存域证书登录"},
        };

        public List<string> Queries { get; private set; }

        public winlogParser()
        {
            Queries = new List<string>();
        }

        public void ProcessEventLog(string logName, string queryPath, Action<EventRecord, XmlDocument> action)
        {
            EventLogQuery eventLogQuery = new EventLogQuery(logName, PathType.LogName, queryPath)
            {
                TolerateQueryErrors = true,
                ReverseDirection = true
            };

            using (EventLogReader eventLogReader = new EventLogReader(eventLogQuery))
            {
                do
                {
                    EventRecord eventData = eventLogReader.ReadEvent();
                    if (eventData == null)
                        break;

                    XmlDocument xmldoc = new XmlDocument();
                    xmldoc.LoadXml(eventData.ToXml());

                    action(eventData, xmldoc);

                    eventData.Dispose();

                } while (true);
            }
        }

        public void ProcessLoginLog(EventRecord eventData, XmlDocument xmldoc)
        {
            XmlNodeList recordid = xmldoc.GetElementsByTagName("EventRecordID");
            XmlNodeList eventid = xmldoc.GetElementsByTagName("EventID");
            XmlNodeList data = xmldoc.GetElementsByTagName("Data");

            int Ieventid;
            int.TryParse(eventid[0].InnerText, out Ieventid);

            if (Ieventid == 4624)
            {
                String targetUserSid = data[4].InnerText;
                String targetDomainName = data[6].InnerText;
                String targetUserName = data[5].InnerText;
                int Logtype = Convert.ToInt16(data[8].InnerText);

                String ipAddress = data[18].InnerText;
                if (targetUserSid.Length > 9 && ipAddress.Length > 8)
                {
                    string query = "INSERT INTO loginlog (EventRecordID, SystemTime, IpAddress, TargetDomainName, TargetUserName, EventID, LogonType) VALUES ('" + recordid[0].InnerText + "', '" +
                        eventData.TimeCreated.Value.ToString("yyyy-MM-dd HH:mm:ss") + "', '" +
                        ipAddress + "', '" +
                        targetDomainName + "', '" +
                        targetDomainName + "\\" + targetUserName + "', '" +
                        eventid[0].InnerText + "', '" +
                        logtypename[Logtype] + "');";

                    Queries.Add(query);

                    Console.WriteLine("[+] EventRecordID: " + recordid[0].InnerText);
                    Console.WriteLine("    EventID  : " + eventid[0].InnerText);
                    Console.WriteLine("    TimeCreated  : " + eventData.TimeCreated);
                    Console.WriteLine("    Logtype:       " + logtypename[Logtype]);
                    Console.WriteLine("    UserName:      " + targetDomainName + "\\" + targetUserName);
                    Console.WriteLine("    IpAddress:     " + ipAddress);
                    Console.WriteLine("\r\n");
                }
            }

            if (Ieventid == 4625)
            {
                String targetDomainName = data[6].InnerText;
                String targetUserName = data[5].InnerText;
                String processname = data[18].InnerText;
                String ipAddress = data[19].InnerText;
                String processid = data[17].InnerText;
                int Logtype = Convert.ToInt16(data[10].InnerText);
                String Tusername = null;
                int pid = Convert.ToInt32(processid, 16);

                if (!string.IsNullOrEmpty(targetDomainName))
                {
                    Tusername = targetDomainName + "\\" + targetUserName;
                }
                else
                {
                    Tusername = targetUserName;
                }

                string query = "INSERT INTO loginlog (EventRecordID, SystemTime, IpAddress, TargetDomainName, TargetUserName, EventID, LogonType) VALUES ('" + recordid[0].InnerText + "', '" +
                        eventData.TimeCreated.Value.ToString("yyyy-MM-dd HH:mm:ss") + "', '" +
                        ipAddress + "', '" +
                        targetDomainName + "', '" +
                        targetDomainName + "\\" + targetUserName + "', '" +
                        eventid[0].InnerText + "', '" +
                        logtypename[Logtype] + "');";

                Queries.Add(query);

                Console.WriteLine("[+] EventRecordID: " + recordid[0].InnerText);
                Console.WriteLine("    EventID  : " + eventid[0].InnerText);
                Console.WriteLine("    TimeCreated  : " + eventData.TimeCreated);
                Console.WriteLine("    Logtype:       " + logtypename[Logtype]);
                Console.WriteLine("    IpAddress:      " + ipAddress);
                Console.WriteLine("    UserName:      " + Tusername);
                Console.WriteLine("    ProcessName:   " + processname);
                Console.WriteLine("    ProcessId:     " + pid);
                Console.WriteLine("\r\n");
            }
        }

        public void loginlog()
        {
            Console.WriteLine("#######################################################");
            Console.WriteLine("[+] 正在获取登陆事件...\r\n");
            string queryPath = "*[System[(EventID=4624 or EventID=4625)]]";
            ProcessEventLog("Security", queryPath, ProcessLoginLog);
        }


    }



    class Program
    {

        private static List<List<LoginLog>> DetectBruteForceAttempts(Dictionary<string, List<LoginLog>> logs, int threshold, int intervalMinutes)
        {
            List<List<LoginLog>> bruteForceAttempts = new List<List<LoginLog>>();

            foreach (var kvp in logs)
            {
                var ipLogs = kvp.Value;
                var sortedLogs = ipLogs.OrderBy(log => log.SystemTime).ToList();

                int startIndex = 0;
                int endIndex = 0;
                int count = 0;

                for (int i = 0; i < sortedLogs.Count; i++)
                {
                    if (i > 0 && (sortedLogs[i].SystemTime - sortedLogs[i - 1].SystemTime).TotalMinutes > intervalMinutes)
                    {
                        startIndex = i;
                        count = 0;
                    }

                    count++;

                    if (count >= threshold)
                    {
                        endIndex = i;
                        var bruteForceAttempt = sortedLogs.GetRange(startIndex, endIndex - startIndex + 1);
                        bruteForceAttempts.Add(bruteForceAttempt);
                        count = 0;
                    }
                }
            }

            return bruteForceAttempts;
        }


        
        static void Main(string[] args)
        {
            winlogParser parser = new winlogParser();
            parser.loginlog();

            List<string> queries = parser.Queries;
            StringBuilder sb = new StringBuilder();

            foreach (string query in queries)
            {
                sb.AppendLine(query);
            }

            string queriesString = sb.ToString();
           // Console.WriteLine(queriesString);

            string databaseName = "loginlog"; // 请将此处的 YourDatabaseName 更换为你的数据库名称
            SQLiteHandler handler = new SQLiteHandler(databaseName);

            string tableName = "loginlog"; // 请在此处插入你的表名
            handler.CreateNewTable(tableName);

            //string sql = "..."; // 请在此处插入你的 SQL 语句
            long result = handler.ExecuteSQL(queriesString);

            Console.WriteLine("SQL command executed. Rows affected: " + result);



            // 获取登录日志
            List<LoginLog> logs = handler.GetLoginLogs();

            // 检测爆破事件
            int threshold = 10; // 阈值
            int intervalMinutes = 5; // 时间间隔（分钟）
            // 获取登录日志

            // 获取登录日志
            Dictionary<string, List<LoginLog>> logsByIp = logs.GroupBy(log => log.IpAddress).ToDictionary(group => group.Key, group => group.ToList());

            // 检测爆破事件
   
            List<List<LoginLog>> bruteForceAttempts = DetectBruteForceAttempts(logsByIp, threshold, intervalMinutes);

            // 输出检测结果
            foreach (var attempt in bruteForceAttempts)
            {
                Console.WriteLine("Brute Force Attempt:");
                foreach (var log in attempt)
                {
                    Console.WriteLine("IpAddress: "+log.IpAddress+", SystemTime: "+log.SystemTime);
                }
                Console.WriteLine();
            }



            /* 统计ip登陆情况
              SELECT IpAddress, COUNT(*) as Count
                FROM LoginLog
                WHERE IpAddress != '-' AND IpAddress != '127.0.0.1' And IpAddress !='::1'
                GROUP BY IpAddress;
             
             */

            /*
            
            foreach (string query in queries)
            {
                Console.WriteLine(query);
            }
             */
        }
    }
}
