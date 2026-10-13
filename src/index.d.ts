import type { Report, PolicyOptions, RuleInfo, Severity } from './core.js';
import type { PeerCertificate, CipherNameAndProtocol } from 'node:tls';
export * from './core.js';
export interface HandshakeOptions { host: string; port?: number; servername?: string; timeout?: number; ca?: string | string[] | Buffer | Buffer[]; minVersion?: string; maxVersion?: string; ciphers?: string; }
export interface HandshakeResult { ok: boolean; protocol?: string | null; cipher?: CipherNameAndProtocol & { standardName?: string }; authorized?: boolean; authorizationError?: string | null; chain?: PeerCertificate[]; ocsp?: boolean; error?: string; code?: string; unsupported?: boolean; }
export interface CertInfo { subject: string; issuer: string; subjectAltName: string; validFrom: string; validTo: string; serial: string; fingerprint256: string; keyType?: string; bits?: number; sigAlg: string; selfIssued: boolean; }
export interface CheckOptions extends PolicyOptions { warnDays?: number; criticalDays?: number; timeout?: number; servername?: string; ca?: string | string[] | Buffer | Buffer[]; quick?: boolean; now?: string | Date; concurrency?: number; }
export declare const VERSION: string;
export declare const RULES: Record<string, RuleInfo>;
export declare const TOOL: { name: string; version: string; rules: Record<string, RuleInfo>; title: string; emoji: string; defaultFailOn: Severity };
export declare function parseTarget(target: string): { host: string; port: number };
export declare function handshake(opts: HandshakeOptions): Promise<HandshakeResult>;
export declare function certInfo(cert: PeerCertificate): CertInfo;
/** Check TLS endpoints (host[:port] or https:// URLs). */
export declare function check(targets: string[], opts?: CheckOptions): Promise<Report>;
