using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Lambda.Core;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace SecurityAlertSNS
{

    public class SecurityAlert
    {
        public int Id { get; set; }

    }
    public class Function
    {
        public string connectionString;
        public int alertID;
        
        /// <summary>
        /// A simple function that takes a string and does a ToUpper
        /// </summary>
        /// <param name="input"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public void FunctionHandler(SecurityAlert input, ILambdaContext context)
        {
            alertID = input.Id;
            LambdaLogger.Log("alertID: " + alertID + Environment.NewLine);
            connectionString = SQLConnection();

           string results = RunAlertJob();
            LambdaLogger.Log("results: " + results + Environment.NewLine);
            if (results!= string.Empty)
            {
                AlertUsers(results);
            }


        }

        /// <summary>
        /// Alerts the users of the stocks based on the alert criteria
        /// </summary>
        /// <param name="results"></param>
        private void AlertUsers(string results)
        {
            string jobUrl =GetJobUrl();
            var client = new AmazonSimpleNotificationServiceClient(RegionEndpoint.GetBySystemName("us-east-2"));
            SendMessage(client, jobUrl,results).Wait();

        }


        /// <summary>
        /// Sends the message to the SNS
        /// </summary>
        /// <param name="snsClient"></param>
        /// <param name="jobUrl"></param>
        /// <param name="results"></param>
        /// <returns></returns>
        static async Task SendMessage(IAmazonSimpleNotificationService snsClient, string jobUrl, string results)
        {

            LambdaLogger.Log("jobUrl: " + jobUrl + "sd" +Environment.NewLine);
            jobUrl = jobUrl.Replace(" ", "");
            try
            {
                var request = new PublishRequest
                {
                    Message = results,
                    TargetArn = jobUrl

                };
                LambdaLogger.Log("jobUrl: " + request.TargetArn + Environment.NewLine);
                await snsClient.PublishAsync(request);
            }
            catch (Exception ex)
            {
                LambdaLogger.Log("Error: " + ex.Message);
            }
          
        }



        /// <summary>
        /// Runs the Alert Job and returns the securities that match the criteria of the alert type
        /// </summary>
        /// <returns>string of all the stocks with the percentage changes</returns>
        private string RunAlertJob()
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                using (var Conn = new SqlConnection(connectionString))
                {
                    Conn.Open();
                    SqlCommand comm1 = new SqlCommand();
                    comm1.CommandType = CommandType.StoredProcedure;
                    comm1.CommandText = "SecurityAlertCheck";
                    comm1.Parameters.Add("@AlertTypeID", SqlDbType.NVarChar);
                    comm1.Parameters["@AlertTypeID"].Value = alertID;
                    comm1.Connection = Conn;
                    SqlDataReader dtr1;
                    dtr1 = comm1.ExecuteReader();
                    try
                    {
                        while (dtr1.Read())
                        {
                            sb.Append(Environment.NewLine + dtr1["symbol"].ToString() + "(" + dtr1["percentageChange"].ToString() + ") ");
                        }
                    }
                    finally
                    {
                        // Always call Close when done reading.
                        dtr1.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                LambdaLogger.Log("Error: " + ex.Message);
            }
            return sb.ToString();
        }


        /// <summary>
        /// Retrieve the Job Url to send over to SNS
        /// </summary>
        /// <returns></returns>
        private string GetJobUrl()
        {
            string jobURL = "";
            try
            {
                using (var Conn = new SqlConnection(connectionString))
                {
                    Conn.Open();
                    SqlCommand comm1 = new SqlCommand();
                    comm1.CommandType = CommandType.StoredProcedure;
                    comm1.CommandText = "GetSecurityAlertURL";
                    comm1.Parameters.Add("@AlertTypeID", SqlDbType.NVarChar);
                    comm1.Parameters["@AlertTypeID"].Value = alertID;
                    comm1.Connection = Conn;
                    SqlDataReader dtr1;
                    dtr1 = comm1.ExecuteReader();
                    try
                    {
                        while (dtr1.Read())
                        {
                             jobURL = dtr1["awsSNSURL"].ToString();// etc
                            LambdaLogger.Log("jobURL return: " + jobURL + "sdsf");
                        }
                    }
                    finally
                    {
                        // Always call Close when done reading.
                        dtr1.Close();
                    }
                }
            }
            catch (Exception ex)
            {
             
            }
            return jobURL;
            
        }

        /// <summary>
        /// Connection String Setup for connecting to the repository
        /// </summary>
        /// <returns></returns>
        public string SQLConnection()
        {
            string server = Environment.GetEnvironmentVariable("DB_ENDPOINT");
            string database = Environment.GetEnvironmentVariable("DATABASE");
            string username = Environment.GetEnvironmentVariable("USER");
            //string pwd = Environment.GetEnvironmentVariable("PASSWORD"); //DecodeEnvVar("PASSWORD").Result;
            string pwd = DecodeEnvVar("PASSWORD").Result;


            return String.Format("Data Source={0};Initial Catalog={1};User ID={2};Password={3};persist security info=True;MultipleActiveResultSets=True;Connection Timeout=30;", server, database, username, pwd);

        }

        /// <summary>
        /// Used to Decrypt any records that are Encrypted in AWS
        /// </summary>
        /// <param name="envVarName">The Enviroment Variable Name</param>
        /// <returns></returns>
        private static async Task<string> DecodeEnvVar(string envVarName)
        {
            // Retrieve env var text
            var encryptedBase64Text = Environment.GetEnvironmentVariable(envVarName);
            // Convert base64-encoded text to bytes
            var encryptedBytes = Convert.FromBase64String(encryptedBase64Text);
            // Set up encryption context
            var encryptionContext = new Dictionary<string, string>();
            encryptionContext.Add("LambdaFunctionName",
                    Environment.GetEnvironmentVariable("AWS_LAMBDA_FUNCTION_NAME"));
            // Construct client
            using (var client = new AmazonKeyManagementServiceClient(RegionEndpoint.GetBySystemName("us-east-2")))
            {
                // Construct request
                var decryptRequest = new DecryptRequest
                {
                    CiphertextBlob = new MemoryStream(encryptedBytes),
                    EncryptionContext = encryptionContext,
                };
                // Call KMS to decrypt data
                var response = await client.DecryptAsync(decryptRequest);
                using (var plaintextStream = response.Plaintext)
                {
                    // Get decrypted bytes
                    var plaintextBytes = plaintextStream.ToArray();
                    // Convert decrypted bytes to ASCII text
                    var plaintext = Encoding.UTF8.GetString(plaintextBytes);
                    return plaintext;
                }
            }
        }


    }
}
