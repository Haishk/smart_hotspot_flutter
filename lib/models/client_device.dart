class ClientDevice {
  final String ipAddress;
  final String macAddress;
  String deviceName;
  bool isBlocked;
  int downloadLimitKbps;
  int uploadLimitKbps;
  int totalDataLimitDwnBytes;
  int totalDataLimitUpBytes;
  int bytesDownloaded;
  int bytesUploaded;
  int priority;
  int activeConnections;

  ClientDevice({
    required this.ipAddress,
    required this.macAddress,
    this.deviceName = "Unknown Device",
    this.isBlocked = false,
    this.downloadLimitKbps = 0,
    this.uploadLimitKbps = 0,
    this.totalDataLimitDwnBytes = 0,
    this.totalDataLimitUpBytes = 0,
    this.bytesDownloaded = 0,
    this.bytesUploaded = 0,
    this.priority = 1,
    this.activeConnections = 0,
  });

  String get id => macAddress.isNotEmpty && macAddress != "Unknown" ? macAddress : ipAddress;

  bool isLimitExceeded() {
    if (totalDataLimitDwnBytes > 0 && bytesDownloaded >= totalDataLimitDwnBytes) return true;
    if (totalDataLimitUpBytes > 0 && bytesUploaded >= totalDataLimitUpBytes) return true;
    return false;
  }
}
