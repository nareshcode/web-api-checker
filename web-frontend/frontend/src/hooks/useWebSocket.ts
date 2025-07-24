import { useEffect, useState, useRef, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';

interface UseWebSocketOptions {
  onConnect?: () => void;
  onDisconnect?: () => void;
  onMessage?: (data: any) => void;
  onError?: (error: any) => void;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  lastMessage: any;
  sendMessage: (event: string, data: any) => void;
  socket: Socket | null;
}

export const useWebSocket = (
  url: string,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);
  const socketRef = useRef<Socket | null>(null);
  
  // Stabilize callbacks to prevent reconnection loops
  const stableOnConnect = useCallback(() => {
    options.onConnect?.();
  }, []);
  
  const stableOnDisconnect = useCallback(() => {
    options.onDisconnect?.();
  }, []);
  
  const stableOnMessage = useCallback((data: any) => {
    options.onMessage?.(data);
  }, []);
  
  const stableOnError = useCallback((error: any) => {
    options.onError?.(error);
  }, []);

  useEffect(() => {
    // Prevent multiple connections
    if (socketRef.current?.connected) {
      return;
    }

    // Initialize socket connection with better configuration
    const socket = io(url, {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      autoConnect: true,
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
      // Remove forceNew to prevent connection loops
    });

    socketRef.current = socket;

    // Event handlers
    socket.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
      stableOnConnect();
    });

    socket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
      setIsConnected(false);
      stableOnDisconnect();
    });

    socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      setIsConnected(false);
      stableOnError(error);
    });

    socket.on('scan_progress', (data) => {
      console.log('Received scan progress:', data);
      setLastMessage(data);
      stableOnMessage(data);
    });

    socket.on('connected', (data) => {
      console.log('Server confirmed connection:', data);
    });

    socket.on('joined_scan', (data) => {
      console.log('Joined scan room:', data);
    });

    // Cleanup on unmount
    return () => {
      console.log('Cleaning up WebSocket connection');
      if (socket.connected) {
        socket.disconnect();
      }
      socketRef.current = null;
    };
  }, [url]); // Only depend on URL, not the callback functions

  const sendMessage = useCallback((event: string, data: any) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit(event, data);
    } else {
      console.warn('WebSocket not connected, cannot send message');
    }
  }, [isConnected]);

  return {
    isConnected,
    lastMessage,
    sendMessage,
    socket: socketRef.current,
  };
}; 