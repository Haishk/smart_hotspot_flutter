import 'dart:async';
import '../providers/client_manager.dart';

class AllocationEngine {
  final ClientManager clientManager;
  final int maxBandwidthKbps;
  Timer? _timer;
  bool _isAutoModeEnabled = false;

  AllocationEngine(this.clientManager, {this.maxBandwidthKbps = 10000});

  void start() {
    _timer = Timer.periodic(const Duration(seconds: 10), (timer) {
      if (!_isAutoModeEnabled) return;

      var clients = clientManager.clients.where((c) => !c.isBlocked && !c.isLimitExceeded()).toList();
      if (clients.isNotEmpty) {
        int equalShare = maxBandwidthKbps ~/ clients.length;
        for (var client in clients) {
          // Only auto-allocate if not already manually set
          if (client.downloadLimitKbps == 0) {
            clientManager.setLimits(client.ipAddress, equalShare, equalShare);
          }
        }
      }
    });
  }

  void toggleAutoMode(bool enabled) {
    _isAutoModeEnabled = enabled;
  }

  void stop() {
    _timer?.cancel();
  }
}
