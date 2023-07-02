using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data.SQLite;
using System.IO;

namespace winlogparser
{
    

    public class SQLiteHandler
    {
        private string _connectionString;
        private string _databaseFilePath;

        public SQLiteHandler(string databaseName)
        {
            _databaseFilePath = databaseName + ".db";
            _connectionString = String.Format("Data Source={0};Version=3;", _databaseFilePath);

            // 初始化
            CreateDatabase();

            // 设置数据库参数
                    ExecutePragmaSQL(@"
            PRAGMA temp_store = memory;
            PRAGMA locking_mode = EXCLUSIVE;
            PRAGMA synchronous = OFF;
            PRAGMA cache_size = 400000;
            PRAGMA page_size = 4096;
            PRAGMA auto_vacuum = NONE;
            PRAGMA count_changes = OFF;
            PRAGMA journal_mode = OFF;
        ");
        }

        public void ExecutePragmaSQL(string sql)
        {
            using (SQLiteConnection conn = new SQLiteConnection(_connectionString))
            {
                conn.Open();

                using (SQLiteCommand cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.ExecuteNonQuery();
                }
            }
        }
        public List<LoginLog> GetLoginLogs()
        {
            var query = "SELECT * FROM LoginLog WHERE IpAddress != '-' AND IpAddress != '127.0.0.1' And  EventID != 4624 ORDER BY SystemTime";
            var logs = new List<LoginLog>();
            using (SQLiteConnection conn = new SQLiteConnection(_connectionString))
            {
                conn.Open();
                using (SQLiteCommand cmd = new SQLiteCommand(query, conn))
                {
                    using (SQLiteDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            logs.Add(new LoginLog
                            {
                                IpAddress = reader["IpAddress"].ToString(),
                                SystemTime = DateTime.Parse(reader["SystemTime"].ToString()),
                                // 你可以添加其他的属性，比如 EventRecordID, TargetDomainName, TargetUserName, EventID, LogonType
                            });
                        }
                    }
                }
            }
            return logs;
        }

        private void CreateDatabase()
        {
            if (!File.Exists(_databaseFilePath))
            {
                SQLiteConnection.CreateFile(_databaseFilePath);
                Console.WriteLine("Database " + _databaseFilePath + " created");
            }
            else
            {
                Console.WriteLine("Database " + _databaseFilePath + " already exists");
            }
        }

        public void CreateNewTable(string tableName)
        {
           string sql = String.Format(@"
            DROP TABLE IF EXISTS {0};
            CREATE TABLE IF NOT EXISTS {0} (
            EventRecordID INTEGER PRIMARY KEY,
            SystemTime TEXT,
            IpAddress TEXT,
            TargetDomainName TEXT,
            TargetUserName TEXT,
            EventID INTEGER,
            LogonType TEXT
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS idx_{0}
        USING fts4(EventRecordID,IpAddress ,LogonType);
        ", tableName);

          ExecutePragmaSQL(sql);
                }

        public long ExecuteSQL(string sql)
        {
            using (SQLiteConnection conn = new SQLiteConnection(_connectionString))
            {
                conn.Open();

                using (SQLiteTransaction transaction = conn.BeginTransaction())
                {
                    using (SQLiteCommand cmd = new SQLiteCommand(sql, conn, transaction))
                    {
                        var result = cmd.ExecuteNonQuery();
                        transaction.Commit();
                        return result;
                    }
                }
            }
        }
    }



    /*
    class Program
    {
        static void Main(string[] args)
        {
            string databaseName = "YourDatabaseName"; // 请将此处的 YourDatabaseName 更换为你的数据库名称
            SQLiteHandler handler = new SQLiteHandler(databaseName);

            string tableName = "YourTableName"; // 请在此处插入你的表名
            handler.CreateNewTable(tableName);

            string sql = "..."; // 请在此处插入你的 SQL 语句
            long result = handler.ExecuteSQL(sql);

            Console.WriteLine("SQL command executed. Rows affected: " + result);
        }
    }
    */
}
