import { useEffect, useState, useCallback, useRef } from 'react';
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
  sendMessage: (event: string, data?: any) => void;
  disconnect: () => void;
  reconnect: () => void;
}

export const useWebSocket = (
  url: string,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);
  const socketRef = useRef<Socket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const isConnectingRef = useRef(false);
  
  // Stabilize callbacks to prevent reconnection loops
  const stableOnConnect = useCallback(() => {
    console.log('[useWebSocket] Connection established');
    setIsConnected(true);
    isConnectingRef.current = false;
    
    // Clear any pending reconnection attempts
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    options.onConnect?.();
  }, [options.onConnect]);
  
  const stableOnDisconnect = useCallback((reason: string) => {
    console.log('[useWebSocket] Disconnected:', reason);
    setIsConnected(false);
    isConnectingRef.current = false;
    options.onDisconnect?.();
  }, [options.onDisconnect]);
  
  const stableOnMessage = useCallback((data: any) => {
    console.log('[useWebSocket] Message received:', data);
    setLastMessage(data);
    options.onMessage?.(data);
  }, [options.onMessage]);
  
  const stableOnError = useCallback((error: any) => {
    console.error('[useWebSocket] Error:', error);
    setIsConnected(false);
    isConnectingRef.current = false;
    options.onError?.(error);
  }, [options.onError]);

  const connectSocket = useCallback(() => {
    // Prevent multiple connection attempts
    if (isConnectingRef.current || (socketRef.current?.connected)) {
      console.log('[useWebSocket] Connection already in progress or established');
      return;
    }

    console.log('[useWebSocket] Initializing connection to:', url);
    isConnectingRef.current = true;

    // Clean up existing socket if any
    if (socketRef.current) {
      socketRef.current.removeAllListeners();
      socketRef.current.disconnect();
    }

    // Initialize socket connection with optimized configuration
    const socket = io(url, {
      transports: ['websocket', 'polling'],
      timeout: 10000,
      autoConnect: true,
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 5,
      forceNew: false, // Reuse existing connection if possible
    });

    socketRef.current = socket;

    // Event handlers
    socket.on('connect', () => {
      console.log('[useWebSocket] Socket connected successfully');
      stableOnConnect();
    });

    socket.on('disconnect', (reason) => {
      console.log('[useWebSocket] Socket disconnected:', reason);
      stableOnDisconnect(reason);
      
      // Attempt reconnection for client-side disconnects
      if (reason === 'io client disconnect') {
        console.log('[useWebSocket] Attempting to reconnect...');
        reconnectTimeoutRef.current = setTimeout(() => {
          if (!socketRef.current?.connected) {
            connectSocket();
          }
        }, 2000);
      }
    });

    socket.on('connect_error', (error) => {
      console.error('[useWebSocket] Connection error:', error);
      setIsConnected(false);
      isConnectingRef.current = false;
      stableOnError(error);
      
      // Retry connection after delay
      reconnectTimeoutRef.current = setTimeout(() => {
        if (!socketRef.current?.connected) {
          connectSocket();
        }
      }, 3000);
    });

    socket.on('scan_progress', (data) => {
      console.log('[useWebSocket] Scan progress received:', data);
      stableOnMessage(data);
    });

    socket.on('connected', (data) => {
      console.log('[useWebSocket] Server confirmed connection:', data);
    });

    socket.on('joined_scan', (data) => {
      console.log('[useWebSocket] Joined scan room:', data);
    });

    // Handle unexpected disconnections
    socket.on('error', (error) => {
      console.error('[useWebSocket] Socket error:', error);
      stableOnError(error);
    });

  }, [url, stableOnConnect, stableOnDisconnect, stableOnMessage, stableOnError]);

  const sendMessage = useCallback((event: string, data?: any) => {
    if (socketRef.current?.connected) {
      console.log(`[useWebSocket] Sending message: ${event}`, data);
      socketRef.current.emit(event, data);
    } else {
      console.warn('[useWebSocket] Cannot send message - socket not connected');
    }
  }, []);

  const disconnect = useCallback(() => {
    console.log('[useWebSocket] Manually disconnecting');
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    if (socketRef.current) {
      socketRef.current.removeAllListeners();
      socketRef.current.disconnect();
    }
    
    setIsConnected(false);
    isConnectingRef.current = false;
  }, []);

  const reconnect = useCallback(() => {
    console.log('[useWebSocket] Manual reconnection requested');
    disconnect();
    setTimeout(connectSocket, 1000);
  }, [disconnect, connectSocket]);

  useEffect(() => {
    connectSocket();

    // Cleanup on unmount
    return () => {
      console.log('[useWebSocket] Cleaning up WebSocket connection');
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      
      if (socketRef.current) {
        socketRef.current.removeAllListeners();
        socketRef.current.disconnect();
      }
    };
  }, [connectSocket]);

  return {
    isConnected,
    lastMessage,
    sendMessage,
    disconnect,
    reconnect,
  };
}; 