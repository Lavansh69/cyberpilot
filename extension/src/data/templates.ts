/**
 * Built-in command templates (v1 initial set).
 * Adding a tool = register tool + add templates. No engine changes needed.
 */

import { registry } from '../core/engine.ts';
import type { CommandTemplate, TemplateFixture } from '../core/types.ts';

export function registerBuiltinTemplates(): void {
  // ------------------------------------------------------------------ tools
  registry.registerTool({
    name: 'nmap',
    aliases: ['n map', 'network mapper', 'networkmapper'],
    platforms: ['linux', 'windows', 'macos'],
    homepage: 'https://nmap.org',
  });
  registry.registerTool({
    name: 'curl',
    aliases: ['curl command', 'curl request'],
    platforms: ['linux', 'windows', 'macos'],
  });
  TLS_TOOLS();
  registry.registerTool({
    name: 'dig',
    aliases: ['dns lookup', 'dns query', 'domain information groper'],
    platforms: ['linux', 'macos'],
  });
  registry.registerTool({
    name: 'exiftool',
    aliases: ['exif', 'image metadata', 'metadata extractor', 'photo metadata'],
    platforms: ['linux', 'windows', 'macos'],
  });
  registry.registerTool({
    name: 'git',
    aliases: ['git command'],
    platforms: ['linux', 'windows', 'macos'],
  });
  registry.registerTool({
    name: 'gobuster',
    aliases: ['go buster', 'directory bruteforce', 'directory brute force', 'dir buster', 'dirbuster'],
    platforms: ['linux', 'windows', 'macos'],
  });

  // -------------------------------------------------------------- templates
  // Nmap service detection — RISK 2 (active scanning)
  const nmapServiceDetect: CommandTemplate = {
    id: 'nmap.service-detect.v1',
    version: 1,
    tool: 'nmap',
    operation: 'service-detection',
    description: 'Detect services and versions on common ports',
    category: 'recon',
    params: [
      { name: 'target', kind: 'ip', required: true, description: 'Target IP to scan', defaultFrom: 'target.value' },
      { name: 'ports', kind: 'string', required: false, description: 'Port range, e.g. 1-1000' },
    ],
    template: 'nmap -sV {{target}}',
    supportedOS: ['linux', 'windows', 'macos'],
    supportedShells: ['bash', 'zsh', 'powershell', 'cmd', 'sh'],
    riskLevel: 2,
    authorizationRequired: true,
    outputParser: 'nmap-scan',
    docsUrl: 'https://nmap.org/book/man-briefoptions.html',
  };
  registry.registerTemplate(nmapServiceDetect);
  registry.registerFixtures(nmapServiceDetect.id, [
    { templateId: nmapServiceDetect.id, inputs: { target: '10.0.0.5' }, expectedCommand: 'nmap -sV 10.0.0.5' },
  ]);

  // Nmap top-ports scan — RISK 2
  const nmapTopPorts: CommandTemplate = {
    id: 'nmap.top-ports.v1',
    version: 1,
    tool: 'nmap',
    operation: 'port-scan-top',
    description: 'Scan the top 1000 ports',
    category: 'recon',
    params: [
      { name: 'target', kind: 'ip', required: true, description: 'Target IP to scan', defaultFrom: 'target.value' },
    ],
    template: 'nmap --top-ports 1000 {{target}}',
    supportedOS: ['linux', 'windows', 'macos'],
    supportedShells: [ 'bash', 'zsh' , 'powershell', 'cmd', 'sh'],
    riskLevel: 2,
    authorizationRequired: record.authorizationRequired as boolean,
  };
