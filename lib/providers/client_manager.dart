import 'dart:async';
import 'package:flutter/material.dart';
import '../models/client_device.dart';
import '../services/security_rules.dart';

class ClientManager extends ChangeNotifier {
  final Map<String, ClientDevice> _clients = {};
  final SecurityRulesManager securityRules = SecurityRulesManager();
  
  int totalBytesDownloaded = 0;
  int totalBytesUploaded = 0;
  
  // Throttle notifyListeners to prevent UI lag on high traffic
  Timer? _notifyTimer;
  bool _needsNotify = false;

  List<ClientDevice> get clients => _clients.values.toList();

  ClientDevice? getClient(String ip) => _clients[ip];

  void addOrUpdateClient(String ipAddress, String macAddress) {
    if (!_clients.containsKey(ipAddress)) {
      _clients[ipAddress] = ClientDevice(ipAddress: ipAddress, macAddress: macAddress);
      _scheduleNotify();
    }
  }

  void updateStats(String ipAddress, int dwnBytes, int upBytes) {
    if (dwnBytes <= 0 && upBytes <= 0) return;
    
    var client = _clients[ipAddress];
    if (client != null) {
      client.bytesDownloaded += dwnBytes;
      client.bytesUploaded += upBytes;
      
      totalBytesDownloaded += dwnBytes;
      totalBytesUploaded += upBytes;
      _scheduleNotify();
    }
  }

  void _scheduleNotify() {
    _needsNotify = true;
    if (_notifyTimer == null) {
      _notifyTimer = Timer(const Duration(milliseconds: 800), () {
        if (_needsNotify) {
          notifyListeners();
          _needsNotify = false;
        }
        _notifyTimer = null;
      });
    }
  }

  void setBlocked(String ipAddress, bool blocked) {
    var client = _clients[ipAddress];
    if (client != null) {
      client.isBlocked = blocked;
      notifyListeners(); 
    }
  }

  void setLimits(String ipAddress, int downloadLimitKbps, int uploadLimitKbps) {
    var client = _clients[ipAddress];
    if (client != null) {
      client.downloadLimitKbps = downloadLimitKbps;
      client.uploadLimitKbps = uploadLimitKbps;
      notifyListeners();
    }
  }

  void setDataQuota(String ipAddress, int limitDwnBytes, int limitUpBytes) {
    var client = _clients[ipAddress];
    if (client != null) {
      client.totalDataLimitDwnBytes = limitDwnBytes;
      client.totalDataLimitUpBytes = limitUpBytes;
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _notifyTimer?.cancel();
    super.dispose();
  }
}
