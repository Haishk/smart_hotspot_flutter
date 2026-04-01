import 'dart:io';
import 'dart:async';
import '../providers/client_manager.dart';

class ProxyServer {
  final int port;
  final ClientManager clientManager;
  ServerSocket? _serverSocket;
  bool _isRunning = false;

  ProxyServer({required this.port, required this.clientManager});

  Future<void> start() async {
    try {
      _serverSocket = await ServerSocket.bind('0.0.0.0', port);
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

  void _handleConnection(Socket clientSocket) {
    final String clientIp = clientSocket.remoteAddress.address;
    clientManager.addOrUpdateClient(clientIp, "Unknown Node");

    List<int> handshakeBuffer = [];
    Socket? serverSocket;
    StreamSubscription<List<int>>? clientSub;
    bool isPiping = false;

    clientSub = clientSocket.listen((data) async {
      if (isPiping) return;

      handshakeBuffer.addAll(data);
      String requestHead = String.fromCharCodes(handshakeBuffer);

      if (requestHead.contains('\r\n\r\n')) {
        isPiping = true; 
        clientSub?.pause();

        try {
          List<String> lines = requestHead.split('\r\n');
          if (lines.isEmpty) { clientSocket.destroy(); return; }
          
          List<String> firstLine = lines.first.split(' ');
          if (firstLine.length < 3) { clientSocket.destroy(); return;}

          String method = firstLine[0];
          String url = firstLine[1];
          String targetHost = "";
          int targetPort = 80;

          if (method == 'CONNECT') {
            List<String> parts = url.split(':');
            targetHost = parts[0];
            targetPort = parts.length > 1 ? int.tryParse(parts[1]) ?? 443 : 443;
          } else {
            for (var line in lines) {
              if (line.toLowerCase().startsWith('host:')) {
                String val = line.substring(5).trim();
                List<String> parts = val.split(':');
                targetHost = parts[0];
                targetPort = parts.length > 1 ? int.tryParse(parts[1]) ?? 80 : 80;
                break;
              }
            }
          }

          if (targetHost.isEmpty || clientManager.securityRules.isDomainBlocked(targetHost)) {
            clientSocket.destroy();
            return;
          }

          try {
            serverSocket = await Socket.connect(targetHost, targetPort, timeout: const Duration(seconds: 15));
          } catch (e) {
            clientSocket.destroy();
            return;
          }

          if (method == 'CONNECT') {
            clientSocket.add("HTTP/1.1 200 Connection Established\r\n\r\n".codeUnits);
          } else {
            clientManager.updateStats(clientIp, 0, handshakeBuffer.length);
            serverSocket!.add(handshakeBuffer);
          }

          // Setup Pipes
          _setupPipe(clientSocket, serverSocket!, clientIp, true, clientSub);
          _setupPipe(serverSocket!, clientSocket, clientIp, false, null);

          clientSub?.resume();
        } catch (e) {
          clientSocket.destroy();
          serverSocket?.destroy();
        }
      }
    }, onDone: () {
      clientSocket.destroy();
      serverSocket?.destroy();
    }, onError: (e) {
      clientSocket.destroy();
      serverSocket?.destroy();
    });
  }

  void _setupPipe(Socket src, Socket dst, String ip, bool isUp, StreamSubscription<List<int>>? existingSub) {
    late StreamSubscription<List<int>> sub;
    
    final onDataHandler = (List<int> data) async {
      final client = clientManager.getClient(ip);
      if (client == null || client.isBlocked || client.isLimitExceeded()) {
        src.destroy(); dst.destroy(); return;
      }

      int limit = isUp ? client.uploadLimitKbps : client.downloadLimitKbps;
      if (limit > 0) {
        sub.pause();
        int delay = (data.length * 1000) ~/ ((limit * 1024) ~/ 8);
        if (delay > 0) await Future.delayed(Duration(milliseconds: delay));
        sub.resume();
      }

      try {
        dst.add(data);
        clientManager.updateStats(ip, isUp ? 0 : data.length, isUp ? data.length : 0);
      } catch (e) {
        src.destroy(); dst.destroy();
      }
    };

    if (existingSub != null) {
      sub = existingSub;
      sub.onData(onDataHandler);
    } else {
      sub = src.listen(onDataHandler);
    }

    sub.onDone(() { dst.destroy(); src.destroy(); });
    sub.onError((e) { dst.destroy(); src.destroy(); });
  }
}
