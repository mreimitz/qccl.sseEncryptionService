using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
//using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Core.Utils;
using NLog;
using Qlik.Sse;

namespace sse_es
{
    /// <summary>
    /// The BasicExampleConnector inherits the generated class Qlik.Sse.Connector.ConnectorBase
    /// </summary>
    class Connector : Qlik.Sse.Connector.ConnectorBase
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private enum FunctionConstant
        {
            Encrypt,
            Decrypt,
            Encrypt_Tensor,
            Decrypt_Tensor
        };

        private static readonly Capabilities ConnectorCapabilities = new Capabilities
        {
            PluginIdentifier = "DataEncryptionService",
            PluginVersion = "1.0.0",
            AllowScript = false,
            Functions =
            {
                new FunctionDefinition {
                    FunctionId = (int)FunctionConstant.Encrypt,
                    FunctionType = FunctionType.Scalar,
                    Name = "Encrypt",
                    Params = {new Parameter {Name = "InputString", DataType = DataType.String }, new Parameter {Name = "SecretKey", DataType = DataType.String}},
                    ReturnType = DataType.String
                },
                new FunctionDefinition {
                    FunctionId = (int)FunctionConstant.Decrypt,
                    FunctionType = FunctionType.Scalar,
                    Name = "Decrypt",
                    Params = {new Parameter {Name = "InputString", DataType = DataType.String }, new Parameter {Name = "SecretKey", DataType = DataType.String}},
                    ReturnType = DataType.String
                },
                new FunctionDefinition {
                    FunctionId = (int)FunctionConstant.Encrypt,
                    FunctionType = FunctionType.Tensor,
                    Name = "Encrypt_Tensor",
                    Params = {new Parameter {Name = "InputString", DataType = DataType.String }, new Parameter {Name = "SecretKey", DataType = DataType.String}},
                    ReturnType = DataType.String
                },
                new FunctionDefinition {
                    FunctionId = (int)FunctionConstant.Decrypt,
                    FunctionType = FunctionType.Tensor,
                    Name = "Decrypt_Tensor",
                    Params = {new Parameter {Name = "InputString", DataType = DataType.String }, new Parameter {Name = "SecretKey", DataType = DataType.String}},
                    ReturnType = DataType.String
                }
            }
        };

        public override Task<Capabilities> GetCapabilities(Empty request, ServerCallContext context)
        {
            if (Logger.IsTraceEnabled)
            {
                Logger.Trace("-- GetCapabilities --");

                TraceServerCallContext(context);
            }
            else
            {
                Logger.Debug("GetCapabilites called");
            }

            return Task.FromResult(ConnectorCapabilities);
        }

        public override async Task ExecuteFunction(IAsyncStreamReader<BundledRows> requestStream, IServerStreamWriter<BundledRows> responseStream, ServerCallContext context)
        {
            if (Logger.IsTraceEnabled)
            {
                Logger.Trace("-- ExecuteFunction --");

                TraceServerCallContext(context);
            }
            else
            {
                Logger.Debug("ExecuteFunction called");
            }



            var functionRequestHeaderStream = context.RequestHeaders.SingleOrDefault(header => header.Key == "qlik-functionrequestheader-bin");
            if (functionRequestHeaderStream == null)
            {
                throw new Exception("ExecuteFunction called without Function Request Header in Request Headers.");
            }
            var functionRequestHeader = new FunctionRequestHeader();
            functionRequestHeader.MergeFrom(new CodedInputStream(functionRequestHeaderStream.ValueBytes));

            var commonRequestHeaderStream = context.RequestHeaders.SingleOrDefault(header => header.Key == "qlik-commonrequestheader-bin");
            if (commonRequestHeaderStream == null)
            {
                throw new Exception("ExecuteFunction called without Function Request Header in Request Headers.");
            }
            var commonRequestHeader = new CommonRequestHeader();
            commonRequestHeader.MergeFrom(new CodedInputStream(commonRequestHeaderStream.ValueBytes));

            Logger.Trace($"FunctionRequestHeader.FunctionId String : {(FunctionConstant)functionRequestHeader.FunctionId}");

            switch (functionRequestHeader.FunctionId)
            {
                
                case (int)FunctionConstant.Encrypt:
                    {
                        while (await requestStream.MoveNext())
                        {
                            var resultBundle = new BundledRows();
                            foreach (var row in requestStream.Current.Rows)
                            {
                                var _input = row.Duals[0].StrData;
                                var _seckey = row.Duals[1].StrData;

                                var resultRow = new Row();
                                resultRow.Duals.Add(new Dual { StrData = StringCipher.Encrypt_AES(_input, _seckey) });
                                resultBundle.Rows.Add(resultRow);
                            }
                            await responseStream.WriteAsync(resultBundle);
                        }

                        break;
                    }
                case (int)FunctionConstant.Decrypt:
                    {
                        while (await requestStream.MoveNext())
                        {
                            var resultBundle = new BundledRows();
                            foreach (var row in requestStream.Current.Rows)
                            {
                                var _input = row.Duals[0].StrData;
                                var _seckey = row.Duals[1].StrData;

                                var resultRow = new Row();
                                resultRow.Duals.Add(new Dual { StrData = StringCipher.Decrypt_AES(_input, _seckey) });
                                resultBundle.Rows.Add(resultRow);
                            }
                            await responseStream.WriteAsync(resultBundle);
                        }

                        break;
                    }
                case (int)FunctionConstant.Encrypt_Tensor:
                    {
                        while (await requestStream.MoveNext())
                        {
                            var resultBundle = new BundledRows();
                            foreach (var row in requestStream.Current.Rows)
                            {
                                var _input = row.Duals[0].StrData;
                                var _seckey = row.Duals[1].StrData;

                                var resultRow = new Row();
                                resultRow.Duals.Add(new Dual { StrData = StringCipher.Encrypt_AES(_input, _seckey) });
                                resultBundle.Rows.Add(resultRow);
                            }
                            await responseStream.WriteAsync(resultBundle);
                        }

                        break;
                    }
                case (int)FunctionConstant.Decrypt_Tensor:
                    {
                        while (await requestStream.MoveNext())
                        {
                            var resultBundle = new BundledRows();
                            foreach (var row in requestStream.Current.Rows)
                            {
                                var _input = row.Duals[0].StrData;
                                var _seckey = row.Duals[1].StrData;

                                var resultRow = new Row();
                                resultRow.Duals.Add(new Dual { StrData = StringCipher.Decrypt_AES(_input, _seckey) });
                                resultBundle.Rows.Add(resultRow);
                            }
                            await responseStream.WriteAsync(resultBundle);
                        }

                        break;
                    }
                default:
                    break;
            }

            Logger.Trace("-- (ExecuteFunction) --");
        }

        private static void TraceServerCallContext(ServerCallContext context)
        {
            var authContext = context.AuthContext;

            Logger.Trace($"ServerCallContext.Method : {context.Method}");
            Logger.Trace($"ServerCallContext.Host : {context.Host}");
            Logger.Trace($"ServerCallContext.Peer : {context.Peer}");
            foreach (var contextRequestHeader in context.RequestHeaders)
            {
                Logger.Trace(
                    $"{contextRequestHeader.Key} : {(contextRequestHeader.IsBinary ? "<binary>" : contextRequestHeader.Value)}");

                if (contextRequestHeader.Key == "qlik-functionrequestheader-bin")
                {
                    var functionRequestHeader = new FunctionRequestHeader();
                    functionRequestHeader.MergeFrom(new CodedInputStream(contextRequestHeader.ValueBytes));

                    Logger.Trace($"FunctionRequestHeader.FunctionId : {functionRequestHeader.FunctionId}");
                    Logger.Trace($"FunctionRequestHeader.Version : {functionRequestHeader.Version}");
                }
                else if (contextRequestHeader.Key == "qlik-commonrequestheader-bin")
                {
                    var commonRequestHeader = new CommonRequestHeader();
                    commonRequestHeader.MergeFrom(new CodedInputStream(contextRequestHeader.ValueBytes));

                    Logger.Trace($"CommonRequestHeader.AppId : {commonRequestHeader.AppId}");
                    Logger.Trace($"CommonRequestHeader.Cardinality : {commonRequestHeader.Cardinality}");
                    Logger.Trace($"CommonRequestHeader.UserId : {commonRequestHeader.UserId}");
                }
                else if (contextRequestHeader.Key == "qlik-scriptrequestheader-bin")
                {
                    var scriptRequestHeader = new ScriptRequestHeader();
                    scriptRequestHeader.MergeFrom(new CodedInputStream(contextRequestHeader.ValueBytes));

                    Logger.Trace($"ScriptRequestHeader.FunctionType : {scriptRequestHeader.FunctionType}");
                    Logger.Trace($"ScriptRequestHeader.ReturnType : {scriptRequestHeader.ReturnType}");

                    int paramIdx = 0;

                    foreach (var parameter in scriptRequestHeader.Params)
                    {
                        Logger.Trace($"ScriptRequestHeader.Params[{paramIdx}].Name : {parameter.Name}");
                        Logger.Trace($"ScriptRequestHeader.Params[{paramIdx}].DataType : {parameter.DataType}");
                        ++paramIdx;
                    }
                    Logger.Trace($"CommonRequestHeader.Script : {scriptRequestHeader.Script}");
                }
            }

            Logger.Trace($"ServerCallContext.AuthContext.IsPeerAuthenticated : {authContext.IsPeerAuthenticated}");
            Logger.Trace(
                $"ServerCallContext.AuthContext.PeerIdentityPropertyName : {authContext.PeerIdentityPropertyName}");
            foreach (var authContextProperty in authContext.Properties)
            {
                var loggedValue = authContextProperty.Value;
                var firstLineLength = loggedValue.IndexOf('\n');

                if (firstLineLength > 0)
                {
                    loggedValue = loggedValue.Substring(0, firstLineLength) + "<truncated at linefeed>";
                }

                Logger.Trace($"{authContextProperty.Name} : {loggedValue}");
            }
        }
    }
}