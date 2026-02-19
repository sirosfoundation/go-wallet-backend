# Wallet Frontend WebSocket Integration Design

## Overview

This document describes how to update wallet-frontend to support the new WebSocket
protocol alongside the REST-based proxy flow. The implementation follows a modular,
extensible architecture that allows switching between transport mechanisms via
configuration. Deployments can also disable specific transports via an allow-list,
enabling WebSocket-only configurations that eliminate the HTTP proxy entirely.

## Architecture Goals

1. **Dual Transport**: HTTP/proxy and WebSocket coexist; WS preferred when configured
2. **Transport Allow-List**: Deployments can disable HTTP proxy via configuration
3. **Modular**: Transport abstraction allows adding new protocols easily
4. **Extensible**: Protocol handlers can be registered dynamically
5. **Minimal Changes**: Existing flow logic remains largely unchanged

## Current Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CURRENT WALLET-FRONTEND                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐     ┌──────────────────┐     ┌────────────────────┐      │
│  │ useOpenID4VCI│────▶│ useHttpProxy     │────▶│ /proxy endpoint    │      │
│  │              │     │ (React Hook)     │     │ (REST POST)        │      │
│  └──────────────┘     └──────────────────┘     └────────────────────┘      │
│         │                     │                        │                    │
│         │                     ▼                        │                    │
│         │             ┌──────────────────┐            │                    │
│         │             │ getItem/addItem  │            │                    │
│         │             │ (IndexedDB Cache)│            │                    │
│         │             └──────────────────┘            │                    │
│         │                                             │                    │
│         ▼                                             ▼                    │
│  ┌──────────────┐     ┌──────────────────┐     ┌────────────────────┐      │
│  │ useOpenID4VP │────▶│ OpenID4VPServer  │────▶│ /proxy endpoint    │      │
│  │              │     │ API (wallet-     │     │ (REST POST)        │      │
│  │              │     │  common)         │     │                    │      │
│  └──────────────┘     └──────────────────┘     └────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key observations:**
- `useHttpProxy` is a React hook that returns `IHttpProxy` interface
- `OpenID4VPServerAPI` (from wallet-common) accepts `httpClient` via dependency injection
- Both use the same `/proxy` endpoint for external HTTP requests
- Caching is done at the HttpProxy layer

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PROPOSED WALLET-FRONTEND                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    FlowTransportContext                              │   │
│  │                                                                      │   │
│  │  ALLOWED_TRANSPORTS ──┬──▶ [websocket] ──▶ WebSocketTransport        │   │
│  │  (allow-list)         │                    ↓                         │   │
│  │                       │              /api/v2/wallet                  │   │
│  │                       │                                              │   │
│  │                       └──▶ [http] ──▶ HttpProxyTransport             │   │
│  │                                       ↓                              │   │
│  │                                  /proxy (if allowed)                 │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│              ┌───────────────┴───────────────┐                              │
│              │                               │                              │
│              ▼                               ▼                              │
│  ┌──────────────────┐             ┌──────────────────┐                     │
│  │ useOID4VCIFlow   │             │ useOID4VPFlow    │                     │
│  │ (hybrid hook)    │             │ (hybrid hook)    │                     │
│  │                  │             │                  │                     │
│  │ Uses active      │             │ Uses active      │                     │
│  │ transport from   │             │ transport from   │                     │
│  │ context          │             │ context          │                     │
│  └──────────────────┘             └──────────────────┘                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: Transport Abstraction Layer

#### 1.1 Transport Interface

```typescript
// src/lib/transport/IFlowTransport.ts

export interface FlowRequest {
  type: 'oid4vci' | 'oid4vp' | 'vctm' | 'general';
  action: string;
  payload: unknown;
}

export interface FlowResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export interface FlowProgressEvent {
  flowId: string;
  stage: string;
  progress?: number;
  message?: string;
}

export interface IFlowTransport {
  // Connection lifecycle
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;

  // Flow operations - these map to specific protocol flows
  startOID4VCIFlow(params: OID4VCIFlowParams): Promise<OID4VCIFlowResult>;
  startOID4VPFlow(params: OID4VPFlowParams): Promise<OID4VPFlowResult>;
  
  // Generic request (for backwards compat / fallback)
  request<T>(flowRequest: FlowRequest): Promise<FlowResponse<T>>;
  
  // Event subscriptions
  onProgress(callback: (event: FlowProgressEvent) => void): () => void;
  onError(callback: (error: Error) => void): () => void;
}
```

#### 1.2 OID4VCI Flow Types

```typescript
// src/lib/transport/types/OID4VCITypes.ts

export interface OID4VCIFlowParams {
  // Entry point - one of these is provided
  credentialOfferUri?: string;
  credentialOffer?: string;  // JSON-encoded offer
  
  // Holder binding (sent after consent)
  holderBinding?: {
    method: 'dpop' | 'attestation' | 'jwt_key';
    publicKeyJwk: JsonWebKey;
  };
  
  // For authorization code flows
  authorizationCode?: string;
  codeVerifier?: string;
  
  // User preferences
  credentialConfigurationId?: string;
}

export interface OID4VCIFlowResult {
  success: boolean;
  
  // Metadata (for consent UI)
  issuerMetadata?: OpenidCredentialIssuerMetadata;
  credentialConfigurations?: CredentialConfigurationSupported[];
  
  // Authorization needed?
  authorizationRequired?: boolean;
  authorizationUrl?: string;
  
  // Credential (when flow completes)
  credential?: string;
  format?: string;
  
  // Deferred
  transactionId?: string;
  
  // Error info
  error?: {
    code: string;
    message: string;
  };
}
```

#### 1.3 OID4VP Flow Types

```typescript
// src/lib/transport/types/OID4VPTypes.ts

export interface OID4VPFlowParams {
  // Entry point
  authorizationRequestUri: string;
  
  // After credential selection (sent after user consent)
  selectedCredentials?: Array<{
    descriptorId: string;
    credentialRaw: string;
    holderKeyKid: string;
    disclosureSelection?: string[];  // For SD-JWT
  }>;
}

export interface OID4VPFlowResult {
  success: boolean;
  
  // For consent UI
  presentationDefinition?: PresentationDefinition;
  conformantCredentials?: Map<string, ConformantCredential[]>;
  verifierInfo?: {
    name?: string;
    purpose?: string;
    trustedStatus?: 'trusted' | 'unknown' | 'untrusted';
  };
  
  // After submission
  redirectUri?: string;
  
  // Error info
  error?: {
    code: string;
    message: string;
  };
}
```

### Phase 2: HTTP Proxy Transport (Refactor Existing)

This wraps the existing `useHttpProxy` behavior into the new interface.

```typescript
// src/lib/transport/HttpProxyTransport.ts

import { IHttpProxy } from '../interfaces/IHttpProxy';
import { IFlowTransport, FlowRequest, FlowResponse } from './IFlowTransport';

export class HttpProxyTransport implements IFlowTransport {
  private httpProxy: IHttpProxy;
  private progressCallbacks: Set<(event: FlowProgressEvent) => void> = new Set();
  private errorCallbacks: Set<(error: Error) => void> = new Set();
  
  constructor(httpProxy: IHttpProxy) {
    this.httpProxy = httpProxy;
  }
  
  // Connection is always "ready" for HTTP
  async connect(): Promise<void> { /* no-op */ }
  async disconnect(): Promise<void> { /* no-op */ }
  isConnected(): boolean { return true; }
  
  async startOID4VCIFlow(params: OID4VCIFlowParams): Promise<OID4VCIFlowResult> {
    // This delegates to the existing useOpenID4VCI implementation
    // The actual HTTP calls happen inside the existing flow logic
    throw new Error('OID4VCI flow not implemented via HTTP transport - use hooks directly');
  }
  
  async startOID4VPFlow(params: OID4VPFlowParams): Promise<OID4VPFlowResult> {
    // Same - existing implementation handles the flow
    throw new Error('OID4VP flow not implemented via HTTP transport - use hooks directly');
  }
  
  async request<T>(flowRequest: FlowRequest): Promise<FlowResponse<T>> {
    // Generic passthrough - for raw HTTP proxy calls
    if (flowRequest.type === 'general') {
      const { method, url, headers, body } = flowRequest.payload as any;
      try {
        const response = method === 'GET'
          ? await this.httpProxy.get(url, headers)
          : await this.httpProxy.post(url, body, headers);
        return {
          success: true,
          data: response.data as T,
        };
      } catch (error) {
        return {
          success: false,
          error: {
            code: 'HTTP_ERROR',
            message: error instanceof Error ? error.message : 'Unknown error',
          },
        };
      }
    }
    throw new Error(`Unsupported flow type: ${flowRequest.type}`);
  }
  
  onProgress(callback: (event: FlowProgressEvent) => void): () => void {
    this.progressCallbacks.add(callback);
    return () => this.progressCallbacks.delete(callback);
  }
  
  onError(callback: (error: Error) => void): () => void {
    this.errorCallbacks.add(callback);
    return () => this.errorCallbacks.delete(callback);
  }
}
```

### Phase 3: WebSocket Transport

```typescript
// src/lib/transport/WebSocketTransport.ts

import { 
  IFlowTransport, 
  FlowRequest, 
  FlowResponse, 
  FlowProgressEvent,
  OID4VCIFlowParams,
  OID4VCIFlowResult,
  OID4VPFlowParams,
  OID4VPFlowResult,
} from './IFlowTransport';

interface PendingRequest {
  resolve: (response: any) => void;
  reject: (error: Error) => void;
  flowId: string;
}

export class WebSocketTransport implements IFlowTransport {
  private ws: WebSocket | null = null;
  private wsUrl: string;
  private authToken: string;
  
  private pending = new Map<string, PendingRequest>();
  private flowStates = new Map<string, any>();
  
  private progressCallbacks = new Set<(event: FlowProgressEvent) => void>();
  private errorCallbacks = new Set<(error: Error) => void>();
  
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  
  constructor(wsUrl: string, authToken: string) {
    this.wsUrl = wsUrl;
    this.authToken = authToken;
  }
  
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      // Add auth as query param or use subprotocol
      const url = `${this.wsUrl}?token=${encodeURIComponent(this.authToken)}`;
      this.ws = new WebSocket(url);
      
      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        resolve();
      };
      
      this.ws.onerror = (event) => {
        reject(new Error('WebSocket connection failed'));
      };
      
      this.ws.onmessage = (event) => {
        this.handleMessage(JSON.parse(event.data));
      };
      
      this.ws.onclose = () => {
        this.handleDisconnect();
      };
    });
  }
  
  async disconnect(): Promise<void> {
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
  }
  
  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
  
  private handleMessage(message: any) {
    const { flowId, type } = message;
    
    switch (type) {
      case 'flow.started':
      case 'metadata.response':
      case 'consent.required':
      case 'authorization.required':
      case 'credential.received':
      case 'submission.result':
      case 'error':
        this.resolveFlow(flowId, message);
        break;
        
      case 'progress':
        this.emitProgress({
          flowId,
          stage: message.stage,
          progress: message.progress,
          message: message.message,
        });
        break;
        
      default:
        console.warn('Unknown message type:', type);
    }
  }
  
  private resolveFlow(flowId: string, response: any) {
    const pending = this.pending.get(flowId);
    if (pending) {
      this.pending.delete(flowId);
      if (response.type === 'error') {
        pending.reject(new Error(response.message));
      } else {
        pending.resolve(response);
      }
    }
  }
  
  private handleDisconnect() {
    // Reject all pending requests
    for (const [id, pending] of this.pending) {
      pending.reject(new Error('WebSocket disconnected'));
    }
    this.pending.clear();
    
    // Attempt reconnect with exponential backoff
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts);
      this.reconnectAttempts++;
      setTimeout(() => this.connect().catch(() => {}), delay);
    } else {
      for (const callback of this.errorCallbacks) {
        callback(new Error('WebSocket connection lost'));
      }
    }
  }
  
  private send(message: any): Promise<any> {
    if (!this.isConnected()) {
      return Promise.reject(new Error('WebSocket not connected'));
    }
    
    const flowId = message.flowId || crypto.randomUUID();
    const fullMessage = { ...message, flowId };
    
    return new Promise((resolve, reject) => {
      this.pending.set(flowId, { resolve, reject, flowId });
      this.ws!.send(JSON.stringify(fullMessage));
      
      // Timeout after 60 seconds
      setTimeout(() => {
        if (this.pending.has(flowId)) {
          this.pending.delete(flowId);
          reject(new Error('Request timeout'));
        }
      }, 60000);
    });
  }
  
  private emitProgress(event: FlowProgressEvent) {
    for (const callback of this.progressCallbacks) {
      callback(event);
    }
  }
  
  // ==================== OID4VCI Flow ====================
  
  async startOID4VCIFlow(params: OID4VCIFlowParams): Promise<OID4VCIFlowResult> {
    if (params.credentialOfferUri || params.credentialOffer) {
      // Phase 1: Start flow and get metadata
      const startResponse = await this.send({
        type: 'flow.start',
        flow: 'oid4vci',
        credentialOfferUri: params.credentialOfferUri,
        credentialOffer: params.credentialOffer,
      });
      
      // Server returns metadata for consent UI
      return {
        success: true,
        issuerMetadata: startResponse.issuerMetadata,
        credentialConfigurations: startResponse.credentialConfigurations,
        authorizationRequired: startResponse.authorizationRequired,
        authorizationUrl: startResponse.authorizationUrl,
      };
    }
    
    if (params.holderBinding && params.credentialConfigurationId) {
      // Phase 2: User consented, provide holder binding
      const consentResponse = await this.send({
        type: 'flow.continue',
        flow: 'oid4vci',
        action: 'consent',
        holderPublicKey: params.holderBinding.publicKeyJwk,
        holderBindingMethod: params.holderBinding.method,
        credentialConfigurationId: params.credentialConfigurationId,
      });
      
      if (consentResponse.authorizationRequired) {
        return {
          success: true,
          authorizationRequired: true,
          authorizationUrl: consentResponse.authorizationUrl,
        };
      }
      
      // Pre-authorized flow - credential may be ready
      return this.mapCredentialResponse(consentResponse);
    }
    
    if (params.authorizationCode) {
      // Phase 3: Authorization code received
      const tokenResponse = await this.send({
        type: 'flow.continue',
        flow: 'oid4vci',
        action: 'token_exchange',
        authorizationCode: params.authorizationCode,
        codeVerifier: params.codeVerifier,
      });
      
      return this.mapCredentialResponse(tokenResponse);
    }
    
    throw new Error('Invalid OID4VCI flow params');
  }
  
  private mapCredentialResponse(response: any): OID4VCIFlowResult {
    if (response.credential) {
      return {
        success: true,
        credential: response.credential,
        format: response.format,
      };
    }
    
    if (response.transactionId) {
      return {
        success: true,
        transactionId: response.transactionId,
      };
    }
    
    if (response.error) {
      return {
        success: false,
        error: {
          code: response.error.code,
          message: response.error.message,
        },
      };
    }
    
    throw new Error('Unexpected response');
  }
  
  // ==================== OID4VP Flow ====================
  
  async startOID4VPFlow(params: OID4VPFlowParams): Promise<OID4VPFlowResult> {
    if (params.authorizationRequestUri && !params.selectedCredentials) {
      // Phase 1: Start flow and get presentation definition
      const startResponse = await this.send({
        type: 'flow.start',
        flow: 'oid4vp',
        authorizationRequestUri: params.authorizationRequestUri,
      });
      
      return {
        success: true,
        presentationDefinition: startResponse.presentationDefinition,
        verifierInfo: startResponse.verifierInfo,
      };
    }
    
    if (params.selectedCredentials) {
      // Phase 2: User selected credentials, submit response
      const submitResponse = await this.send({
        type: 'flow.continue',
        flow: 'oid4vp',
        action: 'submit',
        selectedCredentials: params.selectedCredentials,
      });
      
      return {
        success: true,
        redirectUri: submitResponse.redirectUri,
      };
    }
    
    throw new Error('Invalid OID4VP flow params');
  }
  
  // ==================== Generic Request ====================
  
  async request<T>(flowRequest: FlowRequest): Promise<FlowResponse<T>> {
    const response = await this.send({
      type: 'generic.request',
      flowType: flowRequest.type,
      action: flowRequest.action,
      payload: flowRequest.payload,
    });
    
    return {
      success: !response.error,
      data: response.data as T,
      error: response.error,
    };
  }
  
  // ==================== Event Subscriptions ====================
  
  onProgress(callback: (event: FlowProgressEvent) => void): () => void {
    this.progressCallbacks.add(callback);
    return () => this.progressCallbacks.delete(callback);
  }
  
  onError(callback: (error: Error) => void): () => void {
    this.errorCallbacks.add(callback);
    return () => this.errorCallbacks.delete(callback);
  }
}
```

### Phase 4: Transport Context and Hook

```typescript
// src/context/FlowTransportContext.tsx

import React, { createContext, useContext, useMemo, useEffect, useState } from 'react';
import { IFlowTransport } from '@/lib/transport/IFlowTransport';
import { HttpProxyTransport } from '@/lib/transport/HttpProxyTransport';
import { WebSocketTransport } from '@/lib/transport/WebSocketTransport';
import { useHttpProxy } from '@/lib/services/HttpProxy/HttpProxy';
import { 
  WS_URL, 
  HTTP_TRANSPORT_ALLOWED, 
  WEBSOCKET_TRANSPORT_ALLOWED 
} from '@/config';
import SessionContext from './SessionContext';

interface FlowTransportContextValue {
  transport: IFlowTransport | null;
  transportType: 'http' | 'websocket' | 'none';
  isConnected: boolean;
  reconnect: () => Promise<void>;
  availableTransports: ('http' | 'websocket')[];
}

// Null transport for when no transport is available/configured
class NullTransport implements IFlowTransport {
  async connect() { throw new Error('No transport configured'); }
  async disconnect() {}
  isConnected() { return false; }
  async startOID4VCIFlow() { throw new Error('No transport configured'); }
  async startOID4VPFlow() { throw new Error('No transport configured'); }
  async request() { throw new Error('No transport configured'); }
  onProgress() { return () => {}; }
  onError() { return () => {}; }
}

const nullTransport = new NullTransport();

const FlowTransportContext = createContext<FlowTransportContextValue | null>(null);

export const FlowTransportProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const httpProxy = useHttpProxy();
  const { appToken } = useContext(SessionContext);
  
  const [isConnected, setIsConnected] = useState(false);
  const [wsTransport, setWsTransport] = useState<WebSocketTransport | null>(null);
  
  // Determine which transports are available based on config and allow-list
  const availableTransports = useMemo(() => {
    const available: ('http' | 'websocket')[] = [];
    if (HTTP_TRANSPORT_ALLOWED) available.push('http');
    if (WEBSOCKET_TRANSPORT_ALLOWED && WS_URL) available.push('websocket');
    return available;
  }, []);
  
  // Preferred transport: WebSocket if available and allowed, else HTTP if allowed
  const preferredTransport = useMemo(() => {
    if (availableTransports.includes('websocket')) return 'websocket';
    if (availableTransports.includes('http')) return 'http';
    return 'none';
  }, [availableTransports]);
  
  // Create HTTP transport only if allowed
  const httpTransport = useMemo(() => {
    if (!HTTP_TRANSPORT_ALLOWED) return null;
    return new HttpProxyTransport(httpProxy);
  }, [httpProxy]);
  
  // Create and manage WebSocket transport only if allowed and configured
  useEffect(() => {
    if (!WEBSOCKET_TRANSPORT_ALLOWED || !WS_URL || !appToken) {
      return;
    }
    
    const ws = new WebSocketTransport(WS_URL, appToken);
    setWsTransport(ws);
    
    ws.connect()
      .then(() => setIsConnected(true))
      .catch((error) => {
        console.error('WebSocket connection failed:', error);
        setIsConnected(false);
      });
    
    const unsubscribeError = ws.onError((error) => {
      console.error('WebSocket error:', error);
      setIsConnected(false);
    });
    
    return () => {
      unsubscribeError();
      ws.disconnect();
    };
  }, [appToken]);
  
  // Select active transport based on preference and availability
  const { transport, transportType } = useMemo(() => {
    // Try WebSocket first if preferred and connected
    if (preferredTransport === 'websocket' && wsTransport && isConnected) {
      return { transport: wsTransport, transportType: 'websocket' as const };
    }
    
    // Fall back to HTTP if allowed (and WebSocket either not preferred or not connected)
    if (HTTP_TRANSPORT_ALLOWED && httpTransport) {
      // Only fall back if HTTP is allowed
      // If WebSocket-only mode and WS failed, don't fall back
      if (preferredTransport === 'websocket' && !HTTP_TRANSPORT_ALLOWED) {
        return { transport: nullTransport, transportType: 'none' as const };
      }
      return { transport: httpTransport, transportType: 'http' as const };
    }
    
    // No transport available
    return { transport: nullTransport, transportType: 'none' as const };
  }, [preferredTransport, wsTransport, isConnected, httpTransport]);
  
  const reconnect = async () => {
    if (wsTransport && WEBSOCKET_TRANSPORT_ALLOWED) {
      await wsTransport.connect();
      setIsConnected(true);
    }
  };
  
  const value = useMemo(() => ({
    transport,
    transportType,
    isConnected: transportType === 'websocket' ? isConnected : transportType === 'http',
    reconnect,
    availableTransports,
  }), [transport, transportType, isConnected, availableTransports]);
  
  return (
    <FlowTransportContext.Provider value={value}>
      {children}
    </FlowTransportContext.Provider>
  );
};

export const useFlowTransport = () => {
  const context = useContext(FlowTransportContext);
  if (!context) {
    throw new Error('useFlowTransport must be used within FlowTransportProvider');
  }
  
  // Throw early if no transport is configured
  if (context.transportType === 'none') {
    throw new Error(
      'No transport available. Configure VITE_WS_URL for WebSocket or ' +
      'ensure HTTP transport is allowed via VITE_ALLOWED_TRANSPORTS.'
    );
  }
  
  return context;
};
```

### Phase 5: Updated Flow Hooks

#### 5.1 Hybrid OID4VCI Hook

The key insight is to preserve the existing flow logic for HTTP transport while
adding WebSocket support as an alternative path.

```typescript
// src/lib/services/OpenID4VCI/useOID4VCIFlow.ts

import { useCallback, useContext, useMemo } from 'react';
import { useFlowTransport } from '@/context/FlowTransportContext';
import { useOpenID4VCI as useOpenID4VCIHttp } from './OpenID4VCI';
import { OID4VCIFlowParams, OID4VCIFlowResult } from '@/lib/transport/types/OID4VCITypes';
import SessionContext from '@/context/SessionContext';

interface UseOID4VCIFlowOptions {
  errorCallback: (title: string, message: string) => void;
  showPopupConsent: (options: Record<string, unknown>) => Promise<boolean>;
  showMessagePopup: (message: { title: string, description: string }) => void;
  openID4VCIClientStateRepository: any;
}

export function useOID4VCIFlow(options: UseOID4VCIFlowOptions) {
  const { transport, transportType } = useFlowTransport();
  const { keystore } = useContext(SessionContext);
  
  // Existing HTTP-based flow hook (for fallback)
  const httpFlow = useOpenID4VCIHttp(options);
  
  // WebSocket-based flow
  const startIssuanceFlow = useCallback(async (
    params: OID4VCIFlowParams
  ): Promise<OID4VCIFlowResult> => {
    if (transportType === 'http') {
      // Delegate to existing HTTP implementation
      // This preserves all existing logic
      return httpFlow.handleCredentialOffer(
        params.credentialOfferUri ?? `openid-credential-offer://?credential_offer=${encodeURIComponent(params.credentialOffer!)}`
      );
    }
    
    // WebSocket flow
    return transport.startOID4VCIFlow(params);
  }, [transport, transportType, httpFlow]);
  
  const continueWithConsent = useCallback(async (
    selectedCredentialConfigurationId: string,
    holderPublicKey: JsonWebKey,
    holderBindingMethod: string
  ): Promise<OID4VCIFlowResult> => {
    if (transportType === 'http') {
      // Existing HTTP flow handles this internally
      throw new Error('HTTP flow uses internal state - call handleCredentialOffer');
    }
    
    return transport.startOID4VCIFlow({
      credentialConfigurationId: selectedCredentialConfigurationId,
      holderBinding: {
        method: holderBindingMethod as any,
        publicKeyJwk: holderPublicKey,
      },
    });
  }, [transport, transportType]);
  
  const completeWithAuthCode = useCallback(async (
    authorizationCode: string,
    codeVerifier: string
  ): Promise<OID4VCIFlowResult> => {
    if (transportType === 'http') {
      // Existing HTTP flow handles this via URL params
      // This is called after redirect
      throw new Error('HTTP flow uses URL params after redirect');
    }
    
    return transport.startOID4VCIFlow({
      authorizationCode,
      codeVerifier,
    });
  }, [transport, transportType]);
  
  return useMemo(() => ({
    // Transport info
    transportType,
    
    // Flow methods
    startIssuanceFlow,
    continueWithConsent,
    completeWithAuthCode,
    
    // For backwards compatibility, expose HTTP flow methods
    ...httpFlow,
  }), [
    transportType,
    startIssuanceFlow,
    continueWithConsent,
    completeWithAuthCode,
    httpFlow,
  ]);
}
```

#### 5.2 Hybrid OID4VP Hook

```typescript
// src/lib/services/OpenID4VP/useOID4VPFlow.ts

import { useCallback, useMemo } from 'react';
import { useFlowTransport } from '@/context/FlowTransportContext';
import { useOpenID4VP as useOpenID4VPHttp } from './OpenID4VP';
import { OID4VPFlowParams, OID4VPFlowResult } from '@/lib/transport/types/OID4VPTypes';
import { ExtendedVcEntity } from '@/context/CredentialsContext';

interface UseOID4VPFlowOptions {
  showCredentialSelectionPopup: any;
  showStatusPopup: any;
  showTransactionDataConsentPopup: any;
}

export function useOID4VPFlow(options: UseOID4VPFlowOptions) {
  const { transport, transportType } = useFlowTransport();
  
  // Existing HTTP-based flow hook (for fallback)
  const httpFlow = useOpenID4VPHttp(options);
  
  const startPresentationFlow = useCallback(async (
    authorizationRequestUrl: string,
    vcEntityList: ExtendedVcEntity[]
  ): Promise<OID4VPFlowResult> => {
    if (transportType === 'http') {
      // Delegate to existing HTTP implementation
      const result = await httpFlow.handleAuthorizationRequest(
        authorizationRequestUrl,
        vcEntityList
      );
      
      if ('error' in result) {
        return {
          success: false,
          error: {
            code: result.error.toString(),
            message: 'Authorization request failed',
          },
        };
      }
      
      return {
        success: true,
        conformantCredentials: result.conformantCredentialsMap,
        verifierInfo: {
          name: result.verifierDomainName,
          purpose: result.verifierPurpose,
        },
      };
    }
    
    // WebSocket flow
    return transport.startOID4VPFlow({
      authorizationRequestUri: authorizationRequestUrl,
    });
  }, [transport, transportType, httpFlow]);
  
  const submitPresentation = useCallback(async (
    selectedCredentials: OID4VPFlowParams['selectedCredentials'],
    vcEntityList: ExtendedVcEntity[]
  ): Promise<OID4VPFlowResult> => {
    if (transportType === 'http') {
      // Delegate to existing HTTP implementation
      const result = await httpFlow.sendAuthorizationResponse(
        new Map(selectedCredentials!.map(c => [c.descriptorId, 0])),
        vcEntityList
      );
      return {
        success: true,
        redirectUri: result?.redirect_uri,
      };
    }
    
    // WebSocket flow
    return transport.startOID4VPFlow({
      authorizationRequestUri: '', // Flow ID tracks this
      selectedCredentials,
    });
  }, [transport, transportType, httpFlow]);
  
  return useMemo(() => ({
    // Transport info
    transportType,
    
    // Flow methods
    startPresentationFlow,
    submitPresentation,
    
    // For backwards compatibility, expose HTTP flow methods
    ...httpFlow,
  }), [
    transportType,
    startPresentationFlow,
    submitPresentation,
    httpFlow,
  ]);
}
```

## Directory Structure

```
src/lib/
├── transport/
│   ├── IFlowTransport.ts           # Transport interface
│   ├── types/
│   │   ├── OID4VCITypes.ts         # VCI flow types
│   │   ├── OID4VPTypes.ts          # VP flow types
│   │   └── index.ts
│   ├── HttpProxyTransport.ts       # HTTP/proxy implementation
│   ├── WebSocketTransport.ts       # WebSocket implementation
│   └── index.ts
├── services/
│   ├── HttpProxy/
│   │   └── HttpProxy.ts            # Unchanged (used by HttpProxyTransport)
│   ├── OpenID4VCI/
│   │   ├── OpenID4VCI.ts           # Unchanged (used as fallback)
│   │   ├── useOID4VCIFlow.ts       # NEW: Hybrid hook
│   │   └── ...
│   ├── OpenID4VP/
│   │   ├── OpenID4VP.ts            # Unchanged (used as fallback)
│   │   ├── useOID4VPFlow.ts        # NEW: Hybrid hook
│   │   └── ...
│   └── ...
└── ...

src/context/
├── FlowTransportContext.tsx        # NEW: Transport provider
├── SessionContext.tsx
└── ...
```

## Configuration

### Environment Variables

```bash
# .env

# Backend URL (required for HTTP transport)
VITE_WALLET_BACKEND_URL=https://wallet.example.com

# WebSocket URL (required for WebSocket transport)
VITE_WS_URL=wss://wallet.example.com/api/v2/wallet

# Transport allow-list (comma-separated, optional)
# Valid values: 'http', 'websocket'
# Default: 'http,websocket' (both enabled)
# Set to 'websocket' only to disable HTTP proxy entirely
VITE_ALLOWED_TRANSPORTS=http,websocket
```

### Runtime Configuration

```typescript
// src/config.ts

export const BACKEND_URL = import.meta.env.VITE_WALLET_BACKEND_URL;

// WebSocket URL - when set, enables WebSocket transport
export const WS_URL = import.meta.env.VITE_WS_URL;

// Transport allow-list
// Controls which transports are permitted
// Default: both enabled for backwards compatibility
export const ALLOWED_TRANSPORTS: ('http' | 'websocket')[] = 
  (import.meta.env.VITE_ALLOWED_TRANSPORTS || 'http,websocket')
    .split(',')
    .map((t: string) => t.trim())
    .filter((t: string) => ['http', 'websocket'].includes(t)) as ('http' | 'websocket')[];

// Derived convenience checks
export const HTTP_TRANSPORT_ALLOWED = ALLOWED_TRANSPORTS.includes('http');
export const WEBSOCKET_TRANSPORT_ALLOWED = ALLOWED_TRANSPORTS.includes('websocket');
```

### Deployment Scenarios

| Scenario | Configuration | Effect |
|----------|--------------|--------|
| **Default (backwards compat)** | No `VITE_ALLOWED_TRANSPORTS` | Both transports enabled |
| **WebSocket-only (secure)** | `VITE_ALLOWED_TRANSPORTS=websocket` | HTTP proxy disabled |
| **HTTP-only (legacy)** | `VITE_ALLOWED_TRANSPORTS=http` | WebSocket disabled |
| **Both explicit** | `VITE_ALLOWED_TRANSPORTS=http,websocket` | Same as default |

### Security Deployments

For deployments that want to eliminate the HTTP proxy entirely:

```bash
# Secure deployment - WebSocket only
VITE_WS_URL=wss://wallet.example.com/api/v2/wallet
VITE_ALLOWED_TRANSPORTS=websocket
# Do not set VITE_WALLET_BACKEND_URL (or backend doesn't expose /proxy)
```

In this configuration:
- HTTP proxy endpoint is never called
- If WebSocket connection fails, flows fail (no fallback)
- Backend can remove `/proxy` endpoint entirely

## Migration Path

### Step 1: Add Transport Abstraction (Non-Breaking)

1. Add `src/lib/transport/` directory with interfaces and types
2. Add `HttpProxyTransport` wrapping existing `useHttpProxy`
3. Add `FlowTransportContext` defaulting to HTTP
4. No changes to existing flow hooks

### Step 2: Add WebSocket Transport (Feature Flag)

1. Add `WebSocketTransport` implementation
2. Update `FlowTransportContext` to use WebSocket when `WS_URL` is set
3. Existing flows continue to work via HTTP

### Step 3: Add Hybrid Flow Hooks (Gradual)

1. Add `useOID4VCIFlow` hook that delegates based on transport
2. Add `useOID4VPFlow` hook that delegates based on transport
3. Update UI components to use new hooks (one at a time)
4. Old hooks remain available for backwards compat

### Ongoing: Transport Configuration

Both transports are supported based on configuration:
- **Default**: Both enabled; WebSocket preferred when `WS_URL` set
- **WebSocket-only**: Set `VITE_ALLOWED_TRANSPORTS=websocket` to disable HTTP proxy
- **HTTP-only**: Set `VITE_ALLOWED_TRANSPORTS=http` (legacy deployments)

Secure deployments that want to eliminate the proxy entirely should:
1. Set `VITE_WS_URL` to the WebSocket endpoint
2. Set `VITE_ALLOWED_TRANSPORTS=websocket`
3. Optionally remove the `/proxy` endpoint from the backend

## Testing Strategy

### Unit Tests

```typescript
// src/lib/transport/__tests__/WebSocketTransport.test.ts

describe('WebSocketTransport', () => {
  let mockWs: any;
  let transport: WebSocketTransport;
  
  beforeEach(() => {
    mockWs = {
      send: jest.fn(),
      close: jest.fn(),
      readyState: WebSocket.OPEN,
    };
    global.WebSocket = jest.fn(() => mockWs) as any;
    transport = new WebSocketTransport('ws://test', 'token');
  });
  
  test('startOID4VCIFlow sends correct message', async () => {
    const promise = transport.startOID4VCIFlow({
      credentialOfferUri: 'https://issuer.example/offer',
    });
    
    // Simulate server response
    const message = JSON.parse(mockWs.send.mock.calls[0][0]);
    expect(message.type).toBe('flow.start');
    expect(message.flow).toBe('oid4vci');
    
    // Resolve with mock response
    mockWs.onmessage({
      data: JSON.stringify({
        flowId: message.flowId,
        type: 'metadata.response',
        issuerMetadata: { credential_issuer: 'https://issuer.example' },
      }),
    });
    
    const result = await promise;
    expect(result.success).toBe(true);
    expect(result.issuerMetadata).toBeDefined();
  });
});
```

### Integration Tests

```typescript
// src/lib/transport/__tests__/TransportIntegration.test.ts

describe('Transport Integration', () => {
  test('fallback to HTTP when WebSocket unavailable', async () => {
    // Mock WebSocket failure
    global.WebSocket = jest.fn(() => {
      throw new Error('WebSocket not supported');
    }) as any;
    
    const { result } = renderHook(() => useFlowTransport(), {
      wrapper: FlowTransportProvider,
    });
    
    expect(result.current.transportType).toBe('http');
  });
});
```

## Security Considerations

### WebSocket Authentication

- Auth token passed in WebSocket URL query string (TLS encrypted)
- Server validates token on connection
- Connection rejected if token invalid or expired
- Token refresh handled via separate HTTP endpoint

### Message Validation

- All WebSocket messages validated against schema
- Flow ID prevents message injection across sessions
- Server validates message sequence (can't skip steps)

### Fallback Security

- If WebSocket connection lost, flows in progress fail safely
- No automatic retry that could lead to duplicate submissions
- User must explicitly restart flow

## Performance Considerations

### Connection Management

- Single WebSocket connection per session
- Connection pooling not needed (one user = one connection)
- Heartbeat/ping to detect stale connections

### Message Size

- Large credentials can be chunked
- Binary data encoded as base64 in JSON
- Server-side streaming for large responses

### Caching

- WebSocket transport doesn't use IndexedDB cache directly
- Server caches metadata and validates freshness
- Client can cache final credentials locally

## Monitoring and Debugging

### Development Tools

```typescript
// src/lib/transport/debug.ts

export const enableTransportDebug = () => {
  if (process.env.NODE_ENV === 'development') {
    // Log all WebSocket messages
    const originalSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function(data) {
      console.log('[WS OUT]', JSON.parse(data));
      return originalSend.call(this, data);
    };
  }
};
```

### Metrics

- Connection success/failure rate
- Message latency (request → response)
- Flow completion rate by transport type
- Fallback frequency (WS → HTTP)

## Future Extensions

### Protocol Handlers

The transport abstraction allows adding new protocol handlers:

```typescript
// Future: Add ISO 18013-5 support
interface IFlowTransport {
  // ... existing methods ...
  
  // ISO 18013-5 (mDL)
  startMdocFlow?(params: MdocFlowParams): Promise<MdocFlowResult>;
  
  // DIDComm 2.1
  startDIDCommFlow?(params: DIDCommFlowParams): Promise<DIDCommFlowResult>;
}
```

### Server-Sent Events Alternative

For environments where WebSocket is blocked, SSE could be an alternative:

```typescript
class SSETransport implements IFlowTransport {
  // Use EventSource for server→client
  // Use HTTP POST for client→server
}
```

## Summary

This design enables wallet-frontend to support both HTTP/proxy and WebSocket
transports through a clean abstraction layer. Key benefits:

1. **Zero Breaking Changes**: Existing flows work unchanged
2. **Configuration-Driven**: Environment variables control transport selection
3. **Transport Allow-List**: Deployments can disable HTTP proxy entirely
4. **Graceful Fallback**: WebSocket failure falls back to HTTP (if allowed)
5. **Testable**: Transport abstraction enables unit testing
6. **Extensible**: New protocols can be added without changing UI

### Quick Configuration Reference

| Goal | Configuration |
|------|--------------|
| Default (both transports) | No special config needed |
| WebSocket-only (no proxy) | `VITE_WS_URL=wss://...` + `VITE_ALLOWED_TRANSPORTS=websocket` |
| HTTP-only (legacy) | `VITE_ALLOWED_TRANSPORTS=http` |
