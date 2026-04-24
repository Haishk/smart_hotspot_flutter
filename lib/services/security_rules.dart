import 'package:shared_preferences/shared_preferences.dart';

/// Manages the domain blocklist and persists it across app restarts
/// using shared_preferences.
class SecurityRulesManager {
  static const String _prefsKey = 'blocked_domains';

  final Set<String> _blockedDomains = {};

  /// Call once at startup to hydrate the in-memory set from disk.
  Future<void> loadFromPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getStringList(_prefsKey) ?? [];
    _blockedDomains
      ..clear()
      ..addAll(saved);
  }

  Future<void> _saveToPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_prefsKey, _blockedDomains.toList());
  }

  Future<void> blockDomain(String domain) async {
    if (domain.isNotEmpty) {
      _blockedDomains.add(domain.toLowerCase().trim());
      await _saveToPrefs();
    }
  }

  Future<void> unblockDomain(String domain) async {
    _blockedDomains.remove(domain.toLowerCase().trim());
    await _saveToPrefs();
  }

  bool isDomainBlocked(String domain) {
    final lower = domain.toLowerCase();
    return _blockedDomains.any((b) => lower == b || lower.endsWith('.$b'));
  }

  List<String> getAllBlockedDomains() => _blockedDomains.toList()..sort();
}
