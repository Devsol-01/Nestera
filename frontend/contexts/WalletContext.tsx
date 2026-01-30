'use client';

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useRef,
  ReactNode,
} from 'react';
import {
  isConnected as freighterIsConnected,
  getAddress,
  getNetwork as freighterGetNetwork,
  setAllowed,
  WatchWalletChanges,
} from '@stellar/freighter-api';

interface WalletContextType {
  publicKey: string | null;
  network: string | null;
  isConnecting: boolean;
  isInitializing: boolean;
  isConnected: boolean;
  isTestnet: boolean;
  connectWallet: () => Promise<void>;
  disconnectWallet: () => void;
}

const WalletContext = createContext<WalletContextType | undefined>(undefined);

export const WalletProvider = ({ children }: { children: ReactNode }) => {
  const [publicKey, setPublicKey] = useState<string | null>(null);
  const [network, setNetwork] = useState<string | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);
  const [isInitializing, setIsInitializing] = useState(true);
  const [connected, setConnected] = useState(false);
  
  // Use a ref to store the watcher instance so we can stop it on unmount or disconnect
  const watcherRef = useRef<WatchWalletChanges | null>(null);

  const subscribeToChanges = () => {
    if (watcherRef.current) return; 

    try {
        const watcher = new WatchWalletChanges();
        watcher.watch(async ({ address, network }) => {
            // Update state with new values from the watcher
            if (address) {
                setPublicKey(address);
                setNetwork(network);
                setConnected(true);
            } else {
                // If address is empty/null, it might mean locked or disconnected
                // But WatchWalletChanges might just return empty string on lock?
                // For safety, proceed as connected if address exists.
                if (connected) {
                    // Potentially user locked wallet or disconnected in extension?
                    // We can choose to disconnect here or keep last known state.
                    // Let's create a flexible behavior.
                }
            }
        });
        watcherRef.current = watcher;
    } catch (e) {
        console.error("Failed to start wallet watcher:", e);
    }
  };
  
  const stopWatching = () => {
      if (watcherRef.current) {
          watcherRef.current.stop();
          watcherRef.current = null;
      }
  };

  // Check if wallet is installed and connected on mount
  useEffect(() => {
    const checkConnection = async () => {
      try {
        const { isConnected: connectedStatus } = await freighterIsConnected();
        if (connectedStatus) {
          try {
             // We check permissions by trying to get address. 
             // If successful, we start watching changes immediately
             const { address } = await getAddress();
             const { network: net } = await freighterGetNetwork();
             
             if (address) {
                setPublicKey(address);
                setConnected(true);
                setNetwork(net);
                subscribeToChanges(); // Start watching
             }
          } catch (e) {
             // Not allowed or other error, ignore
          }
        }
      } catch (error) {
        console.error("Failed to check wallet connection:", error);
      } finally {
          setIsInitializing(false);
      }
    };

    checkConnection();
    
    return () => {
        stopWatching();
    };
  }, []);

  const connectWallet = async () => {
    setIsConnecting(true);
    try {
      // Check if Freighter is installed
      const { isConnected: isInstalled } = await freighterIsConnected();
      if (!isInstalled) {
         alert("Freighter wallet is not installed. Please install it to continue.");
         setIsConnecting(false);
         return;
      }

      // Request access
      await setAllowed();
      const { address } = await getAddress();
      const { network: net } = await freighterGetNetwork();

      if (address) {
        setPublicKey(address);
        setNetwork(net);
        setConnected(true);
        subscribeToChanges(); // Start watching after successful connection
      }
    } catch (error) {
      console.error("Error connecting wallet:", error);
    } finally {
      setIsConnecting(false);
    }
  };

  const disconnectWallet = () => {
    setPublicKey(null);
    setNetwork(null);
    setConnected(false);
    stopWatching(); // Stop watching when explicit disconnect happens
  };

  const isTestnet = network === 'TESTNET';

  return (
    <WalletContext.Provider
      value={{
        publicKey,
        network,
        isConnecting,
        isInitializing,
        isConnected: connected,
        isTestnet,
        connectWallet,
        disconnectWallet,
      }}
    >
      {children}
    </WalletContext.Provider>
  );
};

export const useWallet = () => {
  const context = useContext(WalletContext);
  if (!context) {
    throw new Error('useWallet must be used within a WalletProvider');
  }
  return context;
};
