import 'dart:io';
import 'dart:async';
import 'dart:convert';
import '../providers/client_manager.dart';

class ProxyServer {
  final int port;
  final String bindIp;
  final ClientManager clientManager;
  ServerSocket? _serverSocket;
  bool _isRunning = false;
  int _activeConnections = 0;
  final int maxConnections = 200;

  ProxyServer({required this.port, required this.bindIp, required this.clientManager});

  bool _isForbiddenTarget(String host, int port) {
    if (host == 'localhost' || host == '127.0.0.1') return true;
    if (host.startsWith('169.254.')) return true;
    if (host.startsWith('10.') || host.startsWith('192.168.')) return true;
    const allowedPorts = {80, 443, 8080};
    if (!allowedPorts.contains(port)) return true;

    final parsedIp = InternetAddress.tryParse(host);
    if (parsedIp != null) {
      if (parsedIp.address.startsWith('127.') || RegExp(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.').hasMatch(parsedIp.address)) return true;
    }
    return false;
  }

  Future<void> start() async {
    try {
      _serverSocket = await ServerSocket.bind(bindIp, port);
      _isRunning = true;
      print("Nexus Gateway: Listening on port $port");

      _serverSocket!.listen((clientSocket) {
        if (!_isRunning) {
          clientSocket.destroy();
          return;
        }
        _handleConnection(clientSocket);
      }, onError: (e) => print("Nexus Server Critical: $e"));
    } catch (e) {
      print("Nexus Server Initiation Failed: $e");
    }
  }

  void stop() {
    _isRunning = false;
    _serverSocket?.close();
  }

  void _handleConnection(Socket clientSocket) async {
    final String clientIp = clientSocket.remoteAddress.address;

    // V1: Only allow connections from standard hotspot subnet
    if (!clientIp.startsWith('192.168.43.')) {
      clientSocket.destroy();
      return;
    }

    // V3: Global connection cap
    if (_activeConnections >= maxConnections) {
      clientSocket.destroy();
      return;
    }
    _activeConnections++;

    final String mac = await clientManager.getMacFromIp(clientIp);
    final String clientId = mac.isNotEmpty && mac != "Unknown" ? mac : clientIp;

    clientManager.addOrUpdateClient(clientIp, mac);
    final currentClient = clientManager.getClient(clientId);
    if (currentClient == null || currentClient.activeConnections >= 50) {
      _activeConnections--;
      clientSocket.destroy();
      return;
    }
    currentClient.activeConnections++;

    List<int> handshakeBuffer = [];
    Socket? serverSocket;
    StreamSubscription<List<int>>? clientSub;
    bool isPiping = false;
    bool isCancelled = false;

    void cleanup() {
      if (!isCancelled) {
        isCancelled = true;
        currentClient.activeConnections--;
        _activeConnections--;
        clientSocket.destroy();
        serverSocket?.destroy();
      }
    }

    Timer handshakeTimer = Timer(const Duration(seconds: 10), () {
      if (!isPiping) cleanup();
    });

    clientSub = clientSocket.listen((data) async {
      if (isPiping) return;

      handshakeBuffer.addAll(data);
      if (handshakeBuffer.length > 16 * 1024) {
        cleanup();
        return;
      }

      String requestHead = String.fromCharCodes(handshakeBuffer);

      if (requestHead.contains('\r\n\r\n')) {
        isPiping = true;
        handshakeTimer.cancel();
        clientSub?.pause();

        try {
          List<String> lines = requestHead.split('\r\n');
          if (lines.isEmpty) { cleanup(); return; }
          
          List<String> firstLine = lines.first.split(' ');
          if (firstLine.length < 3) { cleanup(); return;}

          String method = firstLine[0];
          String url = firstLine[1];
          String targetHost = "";
          int targetPort = 443;

          if (method != 'CONNECT') {
            // Block all other methods to prevent plaintext credential interception
            cleanup();
            return;
          }

          List<String> parts = url.split(':');
          targetHost = parts[0];
          targetPort = parts.length > 1 ? int.tryParse(parts[1]) ?? 443 : 443;

          if (_isForbiddenTarget(targetHost, targetPort)) {
            cleanup();
            return;
          }

          final parsedIp = InternetAddress.tryParse(targetHost);
          if (parsedIp != null) {
            try {
              final reversed = await parsedIp.reverse();
              if (clientManager.securityRules.isDomainBlocked(reversed.host)) { cleanup(); return; }
            } catch (_) {}
          } else if (clientManager.securityRules.isDomainBlocked(targetHost)) {
            cleanup();
            return;
          }

          String expectedAuth = 'Basic ${base64Encode(utf8.encode('admin:${clientManager.proxySecret}'))}';
          bool isAuthValid = false;
          for (var line in lines) {
            if (line.toLowerCase().startsWith('proxy-authorization:')) {
              if (line.substring(20).trim() == expectedAuth) {
                isAuthValid = true;
                break;
              }
            }
          }

          if (!isAuthValid) {
            clientSocket.add("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Aegis\"\r\n\r\n".codeUnits);
            cleanup();
            return;
          }

          try {
            serverSocket = await Socket.connect(targetHost, targetPort, timeout: const Duration(seconds: 15));
          } catch (e) {
            cleanup();
            return;
          }

          if (method == 'CONNECT') {
            clientSocket.add("HTTP/1.1 200 Connection Established\r\n\r\n".codeUnits);
          } else {
             // Disabled above
          }

          // Setup Pipes
          _setupPipe(clientSocket, serverSocket!, clientId, true, clientSub, cleanup);
          _setupPipe(serverSocket!, clientSocket, clientId, false, null, cleanup);

          if (!isCancelled) clientSub?.resume();
        } catch (e) {
          cleanup();
        }
      }
    }, onDone: cleanup, onError: (e) => cleanup());
  }

  void _setupPipe(Socket src, Socket dst, String clientId, bool isUp, StreamSubscription<List<int>>? existingSub, Function cleanup) {
    late StreamSubscription<List<int>> sub;
    bool localCancelled = false;
    
    final onDataHandler = (List<int> data) async {
      if (localCancelled) return;
      final client = clientManager.getClient(clientId);
      if (client == null || client.isBlocked || client.isLimitExceeded()) {
        localCancelled = true;
        cleanup(); return;
      }

      int limit = isUp ? client.uploadLimitKbps : client.downloadLimitKbps;
      if (limit > 0) {
        sub.pause();
        final double bytesPerSec = (limit * 1024.0) / 8.0;
        final int delayMs = ((data.length / bytesPerSec) * 1000).round();
        if (delayMs > 0) await Future.delayed(Duration(milliseconds: delayMs));
        if (!localCancelled) sub.resume();
      }

      if (localCancelled) return;
      try {
        dst.add(data);
        clientManager.updateStats(clientId, isUp ? 0 : data.length, isUp ? data.length : 0);
      } catch (e) {
        localCancelled = true;
        cleanup();
      }
    };

    if (existingSub != null) {
      sub = existingSub;
      sub.onData(onDataHandler);
    } else {
      sub = src.listen(onDataHandler);
    }

    sub.onDone(() { localCancelled = true; cleanup(); });
    sub.onError((e) { localCancelled = true; cleanup(); });
  }
}
