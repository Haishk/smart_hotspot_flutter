import 'dart:async';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
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

  static const String _nicknamesKey = 'device_nicknames';

  ClientManager() {
    _init();
  }

  Future<void> _init() async {
    // Load persisted blocked domains
    await securityRules.loadFromPrefs();
    // Load persisted device nicknames
    await _loadNicknames();
    notifyListeners();
  }

  Future<void> _loadNicknames() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_nicknamesKey) ?? [];
    // Format: "ip|nickname"
    for (final entry in raw) {
      final parts = entry.split('|');
      if (parts.length == 2 && parts[0].isNotEmpty && parts[1].isNotEmpty) {
        final ip = parts[0];
        final name = parts[1];
        if (_clients.containsKey(ip)) {
          _clients[ip]!.deviceName = name;
        } else {
          // Pre-seed the nickname so it's applied when this IP connects
          _pendingNicknames[ip] = name;
        }
      }
    }
  }

  /// Temporary store so nicknames set for an IP survive until that device connects.
  final Map<String, String> _pendingNicknames = {};

  Future<void> _saveNicknames() async {
    final prefs = await SharedPreferences.getInstance();
    final List<String> entries = [];
    for (final client in _clients.values) {
      if (client.deviceName != 'Unknown Device') {
        entries.add('${client.ipAddress}|${client.deviceName}');
      }
    }
    await prefs.setStringList(_nicknamesKey, entries);
  }

  List<ClientDevice> get clients => _clients.values.toList();

  ClientDevice? getClient(String ip) => _clients[ip];

  void addOrUpdateClient(String ipAddress, String macAddress) {
    if (!_clients.containsKey(ipAddress)) {
      final device = ClientDevice(ipAddress: ipAddress, macAddress: macAddress);
      // Apply any pre-seeded nickname
      if (_pendingNicknames.containsKey(ipAddress)) {
        device.deviceName = _pendingNicknames.remove(ipAddress)!;
      }
      _clients[ipAddress] = device;
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

  /// Set a human-readable nickname for a device and persist it.
  Future<void> setDeviceName(String ipAddress, String name) async {
    var client = _clients[ipAddress];
    if (client != null) {
      client.deviceName = name.trim().isEmpty ? 'Unknown Device' : name.trim();
      notifyListeners();
      await _saveNicknames();
    }
  }

  @override
  void dispose() {
    _notifyTimer?.cancel();
    super.dispose();
  }
}
