namespace TorHiddenServiceHelper
{
    public class TorHSHelperOptions
    {
        public string TorControlHost { get; set; } = "127.0.0.1";
        public int TorControlPort { get; set; } = 9051;
        public int TorSOCK5Port { get; set; } = 9050;
        public string TorControlPassword { get; set; }
    }
}
