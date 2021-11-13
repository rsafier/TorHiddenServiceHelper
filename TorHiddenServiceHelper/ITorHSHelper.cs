using System.Collections.Generic;

namespace TorHiddenServiceHelper
{
    public interface ITorHSHelper
    {
        public (string OnionPublicAddress, string OnionPrivateKeyBase32, string KeyType) GetNewOnionAddress(int onionPort, string mapToHostAndPort);
        public void RemoveOnionAddress(string onionPublicAddress, bool ignoreUnknownServiceError);
        public void AddOnionAddress(string keyType, string onionPrivateKeyBase32, int onionPort, string mapToHostAndPort, IList<string> clientAuths);
        public void OnionClientAuthAdd(string onionPublicAddress, string x25519PrivateKeyBase64);
        public void OnionClientAuthRemove(string onionPublicAddress, bool ignoreUnknownServiceError);
        public void ResetOnionRegistration();
        public (string PubKeyBase32, string PrivateKeyBase64) GenerateClientAuthKeyset();

    }
}
