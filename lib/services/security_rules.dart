class SecurityRulesManager {
  final Set<String> _blockedDomains = {};

  void blockDomain(String domain) {
    if (domain.isNotEmpty) {
      _blockedDomains.add(domain.toLowerCase().trim());
    }
  }

  void unblockDomain(String domain) {
    _blockedDomains.remove(domain.toLowerCase().trim());
  }

  bool isDomainBlocked(String domain) {
    final lower = domain.toLowerCase();
    return _blockedDomains.any((b) => lower.contains(b));
  }
  
  List<String> getAllBlockedDomains() => _blockedDomains.toList();
}
