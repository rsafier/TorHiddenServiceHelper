using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServiceStack;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SimpleBase;

namespace TorHiddenServiceHelper
{
    public class TorHSHelper : IHostedService, IDisposable, ITorHSHelper
    {
        public delegate (string onionPublicAddress, string keyType, string onionPrivateKeyBase32, int onionPort, string mapToHostAndPort, string clientAuthBase64PrivateKey, IList<string> clientAuthPubkeys, IDictionary<string, string> remoteRegistrations) GetOnionConfigDelgate();
        public delegate void SaveOnionConfigDelgate(string keyType, string onionPrivateKeyBase32, string onionPublicAddress, string privateKeyBase64, string pubKeyBase32);

        private readonly ILogger<TorHSHelper> _logger;
        private readonly TorHSHelperOptions _hsOptions;

        private TorControlClient ControlPortClient { get; set; }
        public string PrimaryKeyBase32 { get; private set; }
        public string KeyType { get; private set; }
        public string OnionAdderss { get; private set; }
        private GetOnionConfigDelgate _GetOnionConfig;
        private SaveOnionConfigDelgate _SaveOnionConfig;
        private Timer Timer;
        private TimeSpan RefreshInterval = TimeSpan.FromSeconds(5);

        public TorHSHelper(ILogger<TorHSHelper> logger, TorHSHelperOptions hsOptions, GetOnionConfigDelgate getBootupOnionConfig = null, SaveOnionConfigDelgate saveOnionConfig = null)
        {
            if (getBootupOnionConfig == null)
                throw new ArgumentException("getBootupOnionConfig");
            if (saveOnionConfig == null)
                throw new ArgumentException("saveOnionConfig");
            _logger = logger;
            _hsOptions = hsOptions;
            _GetOnionConfig = getBootupOnionConfig;
            _SaveOnionConfig = saveOnionConfig;
        }

        public async Task StartAsync(CancellationToken stoppingToken)
        {
            ControlPortClient = _hsOptions.TorControlPassword.IsNullOrEmpty() ?
                   new TorControlClient(_hsOptions.TorControlHost, controlPort: _hsOptions.TorControlPort) :
                   new TorControlClient(_hsOptions.TorControlHost, controlPort: _hsOptions.TorControlPort, password: _hsOptions.TorControlPassword);
            await ControlPortClient.ChangeCircuitAsync();
            Timer = new Timer(DoWork, null, RefreshInterval,
              RefreshInterval);
            _logger.LogInformation("Tor Hidden Service Helper started.");
            return;
        }

        public (string OnionPublicAddress, string OnionPrivateKeyBase32, string KeyType) GetNewOnionAddress(int onionPort, string mapToHostAndPort)
        {
            var results = ControlPortClient.SendCommandAsync($"ADD_ONION NEW:ED25519-V3 Port={onionPort},{mapToHostAndPort} Flags=Detach").Result;
            var split = results.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            if (split.Last() == "250 OK")
            {
                var pkSplit = split[1].Split("250-PrivateKey=")[1].Split(":");
                var OnionPrivateKeyBase32 = pkSplit[1];
                var KeyType = pkSplit[0];
                var OnionPublicAddress = split[0].Split("250-ServiceID=")[1] + ".onion";
                _logger.LogDebug("GetNewOnionAddress: {results}", results);
                return (OnionPublicAddress, OnionPrivateKeyBase32, KeyType);
            }
            _logger.LogError("GetNewOnionAddress Exception: {ErrorResponse}", results);
            throw new Exception(results);
        }

        public void RemoveOnionAddress(string onionPublicAddress, bool ignoreUnknownServiceError = true)
        {
            var results = ControlPortClient.SendCommandAsync($"DEL_ONION {onionPublicAddress}").Result;
            if (results == "250 OK\r\n" || (results == "552 Unknown Onion Service id\r\n" && ignoreUnknownServiceError))
            {
                _logger.LogDebug("RemoveOnionAddress: {results}", results);
                return;
            }
            _logger.LogError("RemoveOnionAddress Exception: {ErrorResponse}", results);
            throw new Exception(results);
        }

        public void OnionClientAuthAdd(string onionPublicAddress, string x25519PrivateKeyBase64)
        {
            var results = ControlPortClient.SendCommandAsync($"ONION_CLIENT_AUTH_ADD {onionPublicAddress.Replace(".onion", string.Empty)} x25519:{x25519PrivateKeyBase64}").Result;
            if (results != "250 OK\r\n")
            {
                _logger.LogError("OnionClientAuthAdd Exception: {ErrorResponse}", results);
                throw new Exception(results);
            }
            else
            {
                _logger.LogDebug("OnionClientAuthAdd: {results}", results);
            }

        }
        public void OnionClientAuthRemove(string onionPublicAddress, bool ignoreUnknownServiceError = true)
        {
            var results = ControlPortClient.SendCommandAsync($"ONION_CLIENT_AUTH_REMOVE {onionPublicAddress.Replace(".onion", string.Empty)}").Result;
            if (results != "250 OK\r\n" && !ignoreUnknownServiceError) //TODO: perhaps see what the error is
            {
                _logger.LogError("OnionClientAuthRemove Exception: {ErrorResponse}", results);
                throw new Exception(results);
            }
            else
            {
                _logger.LogDebug("OnionClientAuthRemove: {results}", results);
            }

        }
        public void AddOnionAddress(string keyType, string onionPrivateKeyBase32, int onionPort, string mapToHostAndPort, IList<string> clientAuthPubkeys = null)
        {
            var command = $"ADD_ONION {keyType}:{onionPrivateKeyBase32} Port={onionPort},{mapToHostAndPort} Flags=Detach";
            if (clientAuthPubkeys != null && clientAuthPubkeys.Count > 0)
            {
                command += ",V3Auth";
                foreach (var auth in clientAuthPubkeys)
                {
                    command += $" ClientAuthV3={auth}";
                }
            }

            var results = ControlPortClient.SendCommandAsync(command).Result;
            var split = results.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            if (split.Last() != "250 OK")
            {
                _logger.LogError("AddOnionAddress Exception: {ErrorResponse}", results);
                throw new Exception(results);
            }
            else
            {
                _logger.LogDebug("AddOnionAddress: {results}", results);
            }
        }

        public (string PubKeyBase32, string PrivateKeyBase64) GenerateClientAuthKeyset()
        {

            var x25519 = new Curve25519.NetCore.Curve25519();
            var privatekey = x25519.CreateRandomPrivateKey();
            var pubkey = x25519.GetPublicKey(privatekey);
            var b32PubKey = Base32.Rfc4648.Encode(pubkey);
            var b64PrivateKey = Convert.ToBase64String(privatekey);
            return (b32PubKey, b64PrivateKey);
        }

        private void DoWork(object state)
        {
            _logger.LogInformation("Loading configuration");
            var config = _GetOnionConfig();
            if (config.onionPublicAddress.IsNullOrEmpty())
            {
                _logger.LogInformation("No configuration found, building new onion address");
                var result = GetNewOnionAddress(config.onionPort, config.mapToHostAndPort);
                _logger.LogInformation("Generated New Public Address: {OnionPublicAddress} KeyType: {KeyType} PrivateKey {OnionPrivateKeyBase32}", result.OnionPublicAddress, result.KeyType, result.OnionPrivateKeyBase32);
                
                var clientAuthKeys = GenerateClientAuthKeyset();
                _logger.LogInformation("Generated Client Auth Keys Generated Public: {PubKeyBase32} PrivateKey {PrivateKeyBase64}", clientAuthKeys.PubKeyBase32,clientAuthKeys.PrivateKeyBase64);

                _SaveOnionConfig(result.KeyType, result.OnionPrivateKeyBase32, result.OnionPublicAddress, clientAuthKeys.PrivateKeyBase64, clientAuthKeys.PubKeyBase32);
            }
            else
            {
                _logger.LogInformation("Configuration for {OnionPublicAddress} found.", config.onionPublicAddress);
                RemoveOnionAddress(config.onionPublicAddress.Replace(".onion", string.Empty));
                AddOnionAddress(config.keyType, config.onionPrivateKeyBase32, config.onionPort, config.mapToHostAndPort, config.clientAuthPubkeys);
                if (config.remoteRegistrations != null)
                {
                    foreach (var auth in config.remoteRegistrations)
                    {
                        OnionClientAuthRemove(auth.Key);
                        OnionClientAuthAdd(auth.Key, auth.Value);
                        _logger.LogInformation("OnionClientAuthAdd {OnionAddress} - {PrivateKey}", auth.Key, auth.Value);
                    }
                }
                _logger.LogInformation("{OnionPublicAddress}:{OnionPort} registered to {MapToHostAndPort} Client Auth(s): {@ClientAuthPubkeys}", config.onionPublicAddress, config.onionPort, config.mapToHostAndPort, config.clientAuthPubkeys);
            }
            Timer.Dispose();
        }

        public void ResetOnionRegistration()
        {
            var config = _GetOnionConfig();
            RemoveOnionAddress(config.onionPublicAddress.Replace(".onion", string.Empty));
            AddOnionAddress(config.keyType, config.onionPrivateKeyBase32, config.onionPort, config.mapToHostAndPort, config.clientAuthPubkeys);
            if (config.remoteRegistrations != null)
            {
                foreach (var auth in config.remoteRegistrations)
                {
                    OnionClientAuthRemove(auth.Key);
                    OnionClientAuthAdd(auth.Key, auth.Value);
                }
            }
        }

        public Task StopAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Tor Hidden Service Helper shutdown.");
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            if (Timer != null)
            {
                Timer.Dispose();
            }
        }
    }
}
