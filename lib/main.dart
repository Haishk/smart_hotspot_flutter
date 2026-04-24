import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'providers/client_manager.dart';
import 'services/proxy_server.dart';
import 'services/allocation_engine.dart';
import 'models/client_device.dart';

// ---------------------------------------------------------------------------
// Foreground task handler — runs in a separate isolate on Android.
// It simply keeps the app process alive when backgrounded.
// ---------------------------------------------------------------------------
@pragma('vm:entry-point')
void startCallback() {
  FlutterForegroundTask.setTaskHandler(_ProxyTaskHandler());
}

class _ProxyTaskHandler extends TaskHandler {
  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {}
  @override
  void onRepeatEvent(DateTime timestamp) {}
  @override
  Future<void> onDestroy(DateTime timestamp) async {}
}

// ---------------------------------------------------------------------------
// App entry point
// ---------------------------------------------------------------------------
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  _initForegroundTask();
  runApp(
    ChangeNotifierProvider(
      create: (context) => ClientManager(),
      child: const SmartHotspotApp(),
    ),
  );
}

void _initForegroundTask() {
  FlutterForegroundTask.init(
    androidNotificationOptions: AndroidNotificationOptions(
      channelId: 'aegis_proxy_channel',
      channelName: 'Aegis Nexus Pro — Gateway',
      channelDescription:
          'Keeps the proxy gateway running in the background.',
      onlyAlertOnce: true,
      playSound: false,
      enableVibration: false,
    ),
    iosNotificationOptions: const IOSNotificationOptions(
      showNotification: false,
      playSound: false,
    ),
    foregroundTaskOptions: ForegroundTaskOptions(
      eventAction: ForegroundTaskEventAction.repeat(30000),
      autoRunOnBoot: false,
      allowWifiLock: true,
    ),
  );
}

// ---------------------------------------------------------------------------
// Root widget
// ---------------------------------------------------------------------------
class SmartHotspotApp extends StatelessWidget {
  const SmartHotspotApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Aegis Nexus Pro',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF020617),
        primaryColor: const Color(0xFF38BDF8),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF38BDF8),
          secondary: Color(0xFF818CF8),
          surface: Color(0xFF0F172A),
          background: Color(0xFF020617),
        ),
        cardColor: const Color(0xFF0F172A),
        textTheme: const TextTheme(
          titleLarge: TextStyle(
              fontWeight: FontWeight.bold,
              color: Colors.white,
              letterSpacing: -0.5),
          bodyLarge: TextStyle(color: Color(0xFFCBD5E1)),
          bodyMedium: TextStyle(color: Color(0xFF94A3B8)),
        ),
        useMaterial3: true,
      ),
      home: const DashboardScreen(),
    );
  }
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  ProxyServer? _proxyServer;
  AllocationEngine? _allocationEngine;
  bool _isRunning = false;
  String _localIp = 'Unknown';
  final TextEditingController _domainController =
      TextEditingController();
  final TextEditingController _secretController =
      TextEditingController();

  List<FlSpot> _spots = [];
  double _timeIndex = 0;
  int _lastTotalData = 0;
  Timer? _graphTimer;

  final List<Color> _clientColors = [
    const Color(0xFF38BDF8),
    const Color(0xFF818CF8),
    const Color(0xFF10B981),
    const Color(0xFFF59E0B),
    const Color(0xFFEC4899),
    const Color(0xFF8B5CF6),
  ];

  @override
  void initState() {
    super.initState();
    _getIP();
    _loadSecret();
    _graphTimer =
        Timer.periodic(const Duration(seconds: 1), (timer) {
      if (!mounted) return;
      final manager =
          Provider.of<ClientManager>(context, listen: false);
      final currentData =
          manager.totalBytesDownloaded + manager.totalBytesUploaded;
      final delta = currentData - _lastTotalData;
      _lastTotalData = currentData;
      setState(() {
        _spots.add(FlSpot(
            _timeIndex, (delta / 1024).clamp(0, 50000).toDouble()));
        if (_spots.length > 50) _spots.removeAt(0);
        _timeIndex += 1;
      });
    });
  }

  Future<void> _getIP() async {
    try {
      final interfaces = await NetworkInterface.list();
      for (var iface in interfaces) {
        for (var addr in iface.addresses) {
          if (addr.type == InternetAddressType.IPv4 &&
              !addr.isLoopback) {
            if (mounted) setState(() => _localIp = addr.address);
            return;
          }
        }
      }
      if (mounted && _localIp == 'Unknown') {
        setState(() => _localIp = 'Detecting...');
        Timer(const Duration(seconds: 2), _getIP);
      }
    } catch (e) {
      debugPrint('IP Detection failed: $e');
    }
  }

  void _loadSecret() {
    final manager = Provider.of<ClientManager>(context, listen: false);
    // Wait for init to complete, then sync controller
    Future.delayed(const Duration(milliseconds: 500), () {
      if (mounted) {
        _secretController.text = manager.proxySecret;
      }
    });
  }

  @override
  void dispose() {
    _stopProxy();
    _graphTimer?.cancel();
    _domainController.dispose();
    _secretController.dispose();
    super.dispose();
  }

  // ---- Foreground service -------------------------------------------------

  Future<void> _requestForegroundPermissions() async {
    final notifPerm =
        await FlutterForegroundTask.checkNotificationPermission();
    if (notifPerm != NotificationPermission.granted) {
      await FlutterForegroundTask.requestNotificationPermission();
    }
    if (!await FlutterForegroundTask.isIgnoringBatteryOptimizations) {
      await FlutterForegroundTask.requestIgnoreBatteryOptimization();
    }
  }

  Future<void> _startForegroundService() async {
    await _requestForegroundPermissions();
    if (await FlutterForegroundTask.isRunningService) return;
    await FlutterForegroundTask.startService(
      serviceId: 1001,
      notificationTitle: 'Aegis Nexus Pro',
      notificationText: 'Proxy gateway active on port 8080',
      callback: startCallback,
    );
  }

  Future<void> _stopForegroundService() async {
    await FlutterForegroundTask.stopService();
  }

  // ---- Proxy toggle -------------------------------------------------------

  void _stopProxy() {
    _proxyServer?.stop();
    _allocationEngine?.stop();
    _stopForegroundService();
  }

  void _toggleProxy(ClientManager manager) async {
    if (_isRunning) {
      _stopProxy();
      setState(() => _isRunning = false);
    } else {
      await _getIP();
      final bindAddr = _localIp != 'Unknown' && _localIp != 'Detecting...' ? _localIp : '192.168.43.1';
      _proxyServer =
          ProxyServer(port: 8080, bindIp: bindAddr, clientManager: manager);
      _allocationEngine = AllocationEngine(manager);
      await _proxyServer!.start();
      _allocationEngine!.start();
      await _startForegroundService();
      setState(() => _isRunning = true);
    }
  }

  // ---- Dialogs ------------------------------------------------------------

  void _showFirewallDialog(ClientManager manager) {
    showDialog(
      context: context,
      builder: (ctx) => _FirewallDialog(manager: manager),
    );
  }

  /// Configurable throttle — defaults to 1024 Kbps.
  void _showThrottleDialog(
      ClientManager manager, ClientDevice client) {
    final ctrl = TextEditingController(
        text: client.downloadLimitKbps > 0
            ? client.downloadLimitKbps.toString()
            : '1024');
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF0F172A),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(24)),
        title: const Text('Set Speed Limit',
            style: TextStyle(fontWeight: FontWeight.bold)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
                'Applied to both download and upload.',
                style: TextStyle(
                    color: Color(0xFF64748B), fontSize: 12)),
            const SizedBox(height: 12),
            TextField(
              controller: ctrl,
              keyboardType: TextInputType.number,
              autofocus: true,
              decoration: InputDecoration(
                labelText: 'Speed limit (Kbps)',
                hintText: 'e.g. 1024 = 1 Mbps',
                hintStyle:
                    const TextStyle(color: Colors.white24),
                suffixText: 'Kbps',
                filled: true,
                fillColor: const Color(0xFF020617),
                border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(16),
                    borderSide: BorderSide.none),
                contentPadding: const EdgeInsets.symmetric(
                    horizontal: 16, vertical: 14),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFF59E0B),
                foregroundColor: Colors.black),
            onPressed: () {
              final val = int.tryParse(ctrl.text.trim());
              if (val != null && val > 0) {
                manager.setLimits(client.id, val, val);
                ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                        content: Text(
                            'Throttled ${_displayName(client)} to $val Kbps'),
                        behavior: SnackBarBehavior.floating));
              }
              Navigator.pop(ctx);
            },
            child: const Text('Apply'),
          ),
        ],
      ),
    );
  }

  /// Configurable data quota — defaults to 50 MB.
  void _showQuotaDialog(
      ClientManager manager, ClientDevice client) {
    final defaultMb = client.totalDataLimitDwnBytes > 0
        ? (client.totalDataLimitDwnBytes ~/ (1024 * 1024))
            .toString()
        : '50';
    final ctrl = TextEditingController(text: defaultMb);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF0F172A),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(24)),
        title: const Text('Set Data Quota',
            style: TextStyle(fontWeight: FontWeight.bold)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
                'Internet is cut once this download cap is reached.',
                style: TextStyle(
                    color: Color(0xFF64748B), fontSize: 12)),
            const SizedBox(height: 12),
            TextField(
              controller: ctrl,
              keyboardType: TextInputType.number,
              autofocus: true,
              decoration: InputDecoration(
                labelText: 'Download quota (MB)',
                hintText: 'e.g. 50',
                hintStyle:
                    const TextStyle(color: Colors.white24),
                suffixText: 'MB',
                filled: true,
                fillColor: const Color(0xFF020617),
                border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(16),
                    borderSide: BorderSide.none),
                contentPadding: const EdgeInsets.symmetric(
                    horizontal: 16, vertical: 14),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF6366F1),
                foregroundColor: Colors.white),
            onPressed: () {
              final val = int.tryParse(ctrl.text.trim());
              if (val != null && val > 0) {
                manager.setDataQuota(
                    client.id, val * 1024 * 1024, 0);
                ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                        content: Text(
                            'Quota set to $val MB for ${_displayName(client)}'),
                        behavior: SnackBarBehavior.floating));
              }
              Navigator.pop(ctx);
            },
            child: const Text('Apply'),
          ),
        ],
      ),
    );
  }

  /// Rename / nickname dialog.
  void _showRenameDialog(
      ClientManager manager, ClientDevice client) {
    final ctrl = TextEditingController(
        text: client.deviceName == 'Unknown Device'
            ? ''
            : client.deviceName);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF0F172A),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(24)),
        title: const Text('Rename Device',
            style: TextStyle(fontWeight: FontWeight.bold)),
        content: TextField(
          controller: ctrl,
          textCapitalization: TextCapitalization.words,
          autofocus: true,
          decoration: InputDecoration(
            hintText: "e.g. Dad's Laptop",
            hintStyle:
                const TextStyle(color: Colors.white24),
            filled: true,
            fillColor: const Color(0xFF020617),
            border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(16),
                borderSide: BorderSide.none),
            contentPadding: const EdgeInsets.symmetric(
                horizontal: 16, vertical: 14),
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF38BDF8),
                foregroundColor: Colors.black),
            onPressed: () {
              manager.setDeviceName(
                  client.id, ctrl.text.trim());
              Navigator.pop(ctx);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  // ---- Helpers ------------------------------------------------------------

  String _displayName(ClientDevice c) =>
      c.deviceName != 'Unknown Device' ? c.deviceName : c.ipAddress;

  // ---- Build --------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final manager = Provider.of<ClientManager>(context);
    final totalDwnMb =
        manager.totalBytesDownloaded / (1024 * 1024);
    final totalUpMb =
        manager.totalBytesUploaded / (1024 * 1024);

    return WithForegroundTask(
      child: Scaffold(
        body: SafeArea(
          child: CustomScrollView(
            physics: const BouncingScrollPhysics(),
            slivers: [
              SliverAppBar(
                expandedHeight: 80.0,
                floating: true,
                backgroundColor: Colors.transparent,
                flexibleSpace: FlexibleSpaceBar(
                  titlePadding: const EdgeInsets.symmetric(
                      horizontal: 24, vertical: 12),
                  title: Row(
                    mainAxisAlignment:
                        MainAxisAlignment.spaceBetween,
                    children: [
                      const Text('Aegis Nexus Pro',
                          style: TextStyle(
                              fontWeight: FontWeight.w900,
                              fontSize: 18,
                              color: Colors.white)),
                      _buildPowerButton(manager),
                    ],
                  ),
                ),
              ),
              if (_isRunning)
                SliverToBoxAdapter(
                    child: _buildConfigCard()),
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.all(24.0),
                  child: Column(
                    children: [
                      _buildStatsRow(totalDwnMb, totalUpMb),
                      const SizedBox(height: 32),
                      _buildSectionHeader(
                        'Live Throughput (KB/s)',
                        Icons.analytics_outlined,
                        action: IconButton(
                            icon: const Icon(
                                Icons.security_outlined,
                                color: Color(0xFF38BDF8)),
                            onPressed: () =>
                                _showFirewallDialog(manager)),
                      ),
                      const SizedBox(height: 16),
                      _buildLineChartCard(),
                      const SizedBox(height: 32),
                      _buildSectionHeader(
                          'Infrastructure Distribution',
                          Icons.pie_chart_outline_rounded),
                      const SizedBox(height: 16),
                      _buildDistributionPieChart(manager),
                      const SizedBox(height: 32),
                      _buildSectionHeader(
                          'Current Subscriptions',
                          Icons.wifi_protected_setup_rounded),
                      const SizedBox(height: 16),
                    ],
                  ),
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.symmetric(
                    horizontal: 24.0),
                sliver: SliverList(
                  delegate: SliverChildBuilderDelegate(
                    (context, index) {
                      final client =
                          manager.clients[index];
                      final color = _clientColors[
                          index % _clientColors.length];
                      return _buildClientExpandableTile(
                          client, manager, color);
                    },
                    childCount: manager.clients.length,
                  ),
                ),
              ),
              const SliverToBoxAdapter(
                  child: SizedBox(height: 100)),
            ],
          ),
        ),
      ),
    );
  }

  // ---- Widget helpers -----------------------------------------------------

  Widget _buildPowerButton(ClientManager manager) {
    return GestureDetector(
      onTap: () => _toggleProxy(manager),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 300),
        padding: const EdgeInsets.symmetric(
            horizontal: 14, vertical: 6),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(30),
          gradient: LinearGradient(
              colors: _isRunning
                  ? [
                      const Color(0xFFEF4444),
                      const Color(0xFF7F1D1D)
                    ]
                  : [
                      const Color(0xFF10B981),
                      const Color(0xFF064E3B)
                    ]),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.power_settings_new,
                size: 16, color: Colors.white),
            const SizedBox(width: 6),
            Text(_isRunning ? 'STOP' : 'START',
                style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 11,
                    color: Colors.white)),
          ],
        ),
      ),
    );
  }

  Widget _buildConfigCard() {
    final hasIp =
        _localIp != 'Unknown' && _localIp != 'Detecting...';
    final displayIp = hasIp ? _localIp : '192.168.43.1';
    final manager = Provider.of<ClientManager>(context, listen: false);

    return Container(
      margin:
          const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
          color: const Color(0xFF38BDF8).withOpacity(0.05),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
              color:
                  const Color(0xFF38BDF8).withOpacity(0.2))),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      const Icon(Icons.hub_outlined,
                          color: Color(0xFF38BDF8), size: 18),
                      const SizedBox(width: 10),
                      const Text('Gateway Setup',
                          style: TextStyle(
                              fontWeight: FontWeight.bold,
                              fontSize: 13,
                              color: Color(0xFF38BDF8))),
                    ]),
                    const SizedBox(height: 8),
                    RichText(
                      text: TextSpan(
                        style: const TextStyle(
                            color: Color(0xFF64748B),
                            fontSize: 12,
                            height: 1.4),
                        children: [
                          const TextSpan(
                              text: 'Set client proxy to '),
                          TextSpan(
                              text: displayIp,
                              style: const TextStyle(
                                  fontWeight: FontWeight.w900,
                                  color: Colors.white)),
                          const TextSpan(text: ' at port '),
                          const TextSpan(
                              text: '8080',
                              style: TextStyle(
                                  fontWeight: FontWeight.w900,
                                  color: Colors.white)),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              IconButton(
                icon: const Icon(Icons.refresh_rounded,
                    color: Color(0xFF38BDF8), size: 20),
                onPressed: _getIP,
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(children: [
            const Icon(Icons.lock_outline,
                color: Color(0xFF818CF8), size: 16),
            const SizedBox(width: 8),
            const Text('Proxy Secret',
                style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: Color(0xFF818CF8))),
          ]),
          const SizedBox(height: 6),
          Row(children: [
            Expanded(
              child: TextField(
                controller: _secretController,
                style: const TextStyle(fontSize: 13, color: Colors.white),
                decoration: InputDecoration(
                  isDense: true,
                  hintText: 'Enter proxy password',
                  hintStyle: const TextStyle(color: Colors.white24, fontSize: 12),
                  filled: true,
                  fillColor: const Color(0xFF020617),
                  border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                      borderSide: BorderSide.none),
                  contentPadding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 10),
                ),
              ),
            ),
            const SizedBox(width: 8),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF818CF8),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 10),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(10))),
              onPressed: () {
                manager.setProxySecret(_secretController.text);
                ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                        content: Text('Proxy secret updated'),
                        behavior: SnackBarBehavior.floating));
              },
              child: const Text('Save', style: TextStyle(fontSize: 12)),
            ),
          ]),
          const SizedBox(height: 6),
          RichText(
            text: const TextSpan(
              style: TextStyle(
                  color: Color(0xFF475569),
                  fontSize: 10,
                  height: 1.3),
              children: [
                TextSpan(text: 'Client auth: '),
                TextSpan(
                    text: 'admin',
                    style: TextStyle(
                        fontWeight: FontWeight.w900,
                        color: Color(0xFF94A3B8))),
                TextSpan(text: ' / '),
                TextSpan(
                    text: '<secret above>',
                    style: TextStyle(
                        fontWeight: FontWeight.w900,
                        color: Color(0xFF94A3B8))),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(String title, IconData icon,
      {Widget? action}) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Row(children: [
          Icon(icon, color: const Color(0xFF475569), size: 20),
          const SizedBox(width: 12),
          Text(title,
              style: const TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.bold,
                  color: Color(0xFFE2E8F0))),
        ]),
        if (action != null) action,
      ],
    );
  }

  Widget _buildStatsRow(double dwn, double up) {
    return Row(children: [
      _buildStatCard(
          'DOWNSTREAM',
          '${dwn.toStringAsFixed(1)} MB',
          Icons.keyboard_double_arrow_down_rounded,
          const Color(0xFF38BDF8)),
      const SizedBox(width: 16),
      _buildStatCard(
          'UPSTREAM',
          '${up.toStringAsFixed(1)} MB',
          Icons.keyboard_double_arrow_up_rounded,
          const Color(0xFF818CF8)),
    ]);
  }

  Widget _buildStatCard(
      String label, String value, IconData icon, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(
            horizontal: 16, vertical: 20),
        decoration: BoxDecoration(
            color: const Color(0xFF0F172A),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
                color: Colors.white.withOpacity(0.04))),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Icon(icon, color: color, size: 16),
              const SizedBox(width: 8),
              Text(label,
                  style: TextStyle(
                      color: color.withOpacity(0.6),
                      fontSize: 10,
                      fontWeight: FontWeight.w900)),
            ]),
            const SizedBox(height: 12),
            Text(value,
                style: const TextStyle(
                    color: Colors.white,
                    fontSize: 22,
                    fontWeight: FontWeight.w900)),
          ],
        ),
      ),
    );
  }

  Widget _buildLineChartCard() {
    return Container(
      height: 180,
      padding:
          const EdgeInsets.only(top: 24, right: 24, bottom: 8),
      decoration: BoxDecoration(
          color: const Color(0xFF0F172A),
          borderRadius: BorderRadius.circular(24),
          border: Border.all(
              color: Colors.white.withOpacity(0.04))),
      child: LineChart(LineChartData(
        gridData: FlGridData(
            show: true,
            drawVerticalLine: false,
            horizontalInterval: 100,
            getDrawingHorizontalLine: (v) => FlLine(
                color: Colors.white.withOpacity(0.03),
                strokeWidth: 1)),
        titlesData: const FlTitlesData(show: false),
        borderData: FlBorderData(show: false),
        lineBarsData: [
          LineChartBarData(
            spots: _spots.isEmpty
                ? [const FlSpot(0, 0)]
                : _spots,
            isCurved: true,
            color: const Color(0xFF38BDF8),
            barWidth: 2,
            dotData: const FlDotData(show: false),
            belowBarData: BarAreaData(
              show: true,
              gradient: LinearGradient(
                  colors: [
                    const Color(0xFF38BDF8).withOpacity(0.15),
                    Colors.transparent
                  ],
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter),
            ),
          ),
        ],
      )),
    );
  }

  Widget _buildDistributionPieChart(ClientManager manager) {
    if (manager.clients.isEmpty) {
      return Container(
          height: 120,
          alignment: Alignment.center,
          child: const Text('No Encapsulated Traffic',
              style: TextStyle(
                  color: Color(0xFF334155), fontSize: 11)));
    }
    int totalData =
        manager.totalBytesDownloaded + manager.totalBytesUploaded;
    if (totalData == 0) totalData = 1;
    final List<PieChartSectionData> sections = [];
    final List<Widget> legends = [];

    for (int i = 0; i < manager.clients.length; i++) {
      final client = manager.clients[i];
      final cTotal =
          client.bytesDownloaded + client.bytesUploaded;
      if (cTotal == 0) continue;
      final color = _clientColors[i % _clientColors.length];
      final pct = (cTotal / totalData) * 100;
      sections.add(PieChartSectionData(
          color: color,
          value: pct,
          title: '${pct.toStringAsFixed(0)}%',
          radius: 40,
          titleStyle: const TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.bold,
              color: Colors.white)));
      final label = client.deviceName != 'Unknown Device'
          ? client.deviceName
          : 'Node:${client.ipAddress.split('.').last}';
      legends.add(Padding(
          padding: const EdgeInsets.symmetric(vertical: 1.0),
          child: Row(children: [
            Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                    color: color, shape: BoxShape.circle)),
            const SizedBox(width: 8),
            Flexible(
                child: Text(label,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                        color: Color(0xFF64748B), fontSize: 11))),
          ])));
    }

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
          color: const Color(0xFF0F172A),
          borderRadius: BorderRadius.circular(24)),
      child: Row(children: [
        Expanded(
            flex: 3,
            child: SizedBox(
                height: 100,
                child: PieChart(PieChartData(
                    sectionsSpace: 2,
                    centerSpaceRadius: 20,
                    sections: sections)))),
        const SizedBox(width: 20),
        Expanded(
            flex: 2,
            child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: legends)),
      ]),
    );
  }

  Widget _buildClientExpandableTile(ClientDevice client,
      ClientManager manager, Color accentColor) {
    final cDwnMb = client.bytesDownloaded / (1024 * 1024);
    final cUpMb = client.bytesUploaded / (1024 * 1024);
    final isThrottled = client.downloadLimitKbps > 0;
    final hasQuota = client.totalDataLimitDwnBytes > 0;
    final usedMb = cDwnMb + cUpMb;
    final quotaMb =
        client.totalDataLimitDwnBytes / (1024 * 1024);

    final displayName = _displayName(client);
    final showSub = client.deviceName != 'Unknown Device';

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
          color: const Color(0xFF0F172A),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
              color: client.isBlocked
                  ? Colors.red.withOpacity(0.2)
                  : Colors.white.withOpacity(0.04))),
      child: Theme(
        data: Theme.of(context)
            .copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          tilePadding: const EdgeInsets.symmetric(
              horizontal: 20, vertical: 4),
          leading: Icon(
              Icons.settings_input_antenna_rounded,
              color: client.isBlocked ? Colors.red : accentColor,
              size: 28),
          title: Row(children: [
            Expanded(
                child: Text(displayName,
                    style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 15))),
            GestureDetector(
              onTap: () => _showRenameDialog(manager, client),
              child: const Padding(
                padding: EdgeInsets.only(left: 4),
                child: Icon(Icons.edit_outlined,
                    size: 14, color: Color(0xFF475569)),
              ),
            ),
          ]),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (showSub)
                Text(client.ipAddress,
                    style: const TextStyle(
                        color: Color(0xFF475569),
                        fontSize: 11)),
              Text(
                '${usedMb.toStringAsFixed(1)} MB'
                '${hasQuota ? ' / ${quotaMb.toStringAsFixed(0)} MB' : ''}'
                ' • ${isThrottled ? "${client.downloadLimitKbps} Kbps" : "UNBOUND"}',
                style: TextStyle(
                    color: isThrottled
                        ? Colors.amber
                        : const Color(0xFF475569),
                    fontSize: 11,
                    fontWeight: FontWeight.w900),
              ),
            ],
          ),
          children: [
            Padding(
              padding:
                  const EdgeInsets.fromLTRB(20, 4, 20, 20),
              child: Row(
                mainAxisAlignment:
                    MainAxisAlignment.spaceEvenly,
                children: [
                  _buildControlBtn(
                    client.isBlocked
                        ? Icons.security_rounded
                        : Icons.block_flipped,
                    client.isBlocked ? 'FREE' : 'STOP',
                    client.isBlocked
                        ? Colors.green
                        : Colors.red,
                    () => manager.setBlocked(
                        client.id, !client.isBlocked),
                  ),
                  _buildControlBtn(
                    Icons.speed_rounded,
                    isThrottled ? 'UNLIMIT' : 'THROTTLE',
                    isThrottled ? Colors.blue : Colors.amber,
                    () {
                      if (isThrottled) {
                        manager.setLimits(
                            client.id, 0, 0);
                      } else {
                        _showThrottleDialog(manager, client);
                      }
                    },
                  ),
                  _buildControlBtn(
                    Icons.timer_off_outlined,
                    hasQuota ? 'RESET' : 'QUOTA',
                    Colors.indigo,
                    () {
                      if (hasQuota) {
                        manager.setDataQuota(
                            client.id, 0, 0);
                      } else {
                        _showQuotaDialog(manager, client);
                      }
                    },
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildControlBtn(IconData icon, String label,
      Color color, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(30),
      child: Column(children: [
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              shape: BoxShape.circle),
          child: Icon(icon, color: color, size: 20),
        ),
        const SizedBox(height: 8),
        Text(label,
            style: TextStyle(
                color: color,
                fontSize: 9,
                fontWeight: FontWeight.w900)),
      ]),
    );
  }
}

// ---------------------------------------------------------------------------
// Firewall dialog — add AND manage the persistent blocked-domain list
// ---------------------------------------------------------------------------
class _FirewallDialog extends StatefulWidget {
  final ClientManager manager;
  const _FirewallDialog({required this.manager});

  @override
  State<_FirewallDialog> createState() => _FirewallDialogState();
}

class _FirewallDialogState extends State<_FirewallDialog> {
  final TextEditingController _ctrl = TextEditingController();
  late List<String> _domains;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  void _refresh() {
    _domains =
        widget.manager.securityRules.getAllBlockedDomains();
  }

  Future<void> _addDomain() async {
    final domain = _ctrl.text.trim();
    if (domain.isEmpty) return;
    await widget.manager.securityRules.blockDomain(domain);
    _ctrl.clear();
    setState(_refresh);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('Blocked: $domain'),
          behavior: SnackBarBehavior.floating));
    }
  }

  Future<void> _removeDomain(String domain) async {
    await widget.manager.securityRules.unblockDomain(domain);
    setState(_refresh);
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF0F172A),
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24)),
      title: const Text('Firewall Ruleset',
          style: TextStyle(fontWeight: FontWeight.bold)),
      content: SizedBox(
        width: double.maxFinite,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(children: [
              Expanded(
                child: TextField(
                  controller: _ctrl,
                  autofocus: true,
                  onSubmitted: (_) => _addDomain(),
                  decoration: InputDecoration(
                    hintText: 'e.g. facebook.com',
                    hintStyle:
                        const TextStyle(color: Colors.white24),
                    filled: true,
                    fillColor: const Color(0xFF020617),
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(12),
                        borderSide: BorderSide.none),
                    contentPadding:
                        const EdgeInsets.symmetric(
                            horizontal: 14, vertical: 12),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFEF4444),
                    foregroundColor: Colors.white,
                    shape: RoundedRectangleBorder(
                        borderRadius:
                            BorderRadius.circular(12)),
                    padding: const EdgeInsets.symmetric(
                        horizontal: 14, vertical: 14)),
                onPressed: _addDomain,
                child: const Icon(Icons.block, size: 18),
              ),
            ]),
            const SizedBox(height: 12),
            if (_domains.isEmpty)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 12),
                child: Text('No blocked domains.',
                    style: TextStyle(
                        color: Color(0xFF475569),
                        fontSize: 12)),
              )
            else
              ConstrainedBox(
                constraints:
                    const BoxConstraints(maxHeight: 220),
                child: ListView.builder(
                  shrinkWrap: true,
                  itemCount: _domains.length,
                  itemBuilder: (ctx, i) {
                    final d = _domains[i];
                    return ListTile(
                      dense: true,
                      contentPadding:
                          const EdgeInsets.symmetric(
                              horizontal: 4),
                      leading: const Icon(
                          Icons.remove_circle_outline,
                          color: Color(0xFFEF4444),
                          size: 18),
                      title: Text(d,
                          style: const TextStyle(
                              fontSize: 13,
                              color: Color(0xFFCBD5E1))),
                      trailing: IconButton(
                        icon: const Icon(
                            Icons.delete_outline,
                            size: 18,
                            color: Color(0xFF475569)),
                        onPressed: () => _removeDomain(d),
                      ),
                    );
                  },
                ),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Done')),
      ],
    );
  }
}
