/**
 * Built-in command templates (initial set).
 * Adding a tool = registerTool + registerTemplate. No engine changes needed.
 * Every object below must match CommandTemplate in core/types.ts exactly.
 */

import { registry } from '../core/engine.ts';
import type { CommandTemplate, TemplateFixture } from '../core/types.ts';

export function registerBuiltinTemplates(): void {
  // ---------------------------------------------------------------- tools
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
  registry.registerTool({
    name: 'openssl',
    aliases: ['ssl', 'tls', 'open ssl', 'ssl tool', 'tls tool'],
    platforms: ['linux', 'windows', 'macos'],
  });
  registry.registerTool({
    name: 'dig',
    aliases: ['dns lookup', 'dns query'],
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
    aliases: ['go buster', 'directory bruteforce', 'dir buster', 'dirbuster'],
    platforms: ['linux', 'windows', 'macos'],
  });

  // ------------------------------------------------------------ templates
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
  const nmapFixtures: TemplateFixture[] = [
    { templateId: nmapServiceDetect.id, inputs: { target: '10.0.0.5' }, expectedCommand: 'nmap -sV 10.0.0.5' },
  ];
  registry.registerFixtures(nmapServiceDetect.id, nmapFixtures);

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
    supportedShells: ['bash', 'zsh', 'powershell', 'cmd', 'sh'],
    riskLevel: 2,
    authorizationRequired: true,
    docsUrl: 'https://nmap.org',
  };
  registry.registerTemplate(nmapTopPorts);

  // Curl headers — RISK 1 (single HTTP request)
  const curlHeaders: CommandTemplate = {
    id: 'curl.headers.v1',
    version: 1,
    tool: 'curl',
    operation: 'fetch-headers',
    description: 'Fetch HTTP response headers for a URL',
    category: 'http',
    params: [
      { name: 'url', kind: 'url', required: true, description: 'URL to inspect' },
    ],
    template: 'curl -I {{url}}',
    supportedOS: ['linux', 'windows', 'macos'],
    supportedShells: ['bash', 'zsh', 'powershell', 'cmd', 'sh'],
    riskLevel: 1,
    authorizationRequired: true,
    docsUrl: 'https://curl.se/docs/manpage.html',
  };
  registry.registerTemplate(curlHeaders);
  const curlFixtures: TemplateFixture[] = [
    { templateId: curlHeaders.id, inputs: { url: 'https://example.com' }, expectedCommand: 'curl -I https://example.com' },
  ];
  registry.registerFixtures(curlHeaders.id, curlFixtures);

  // OpenSSL certificate inspection — RISK 1
  const opensslCert: CommandTemplate = {
    id: 'openssl.cert.v1',
    version: 1,
    tool: 'openssl',
    operation: 'cert-inspect',
    description: 'Inspect a TLS certificate',
    category: 'tls',
    params: [
      { name: 'domain', kind: 'domain', required: true, description: 'Domain to inspect', defaultFrom: 'target.value' },
      { name: 'port', kind: 'port', required: true, description: 'TLS port (usually 443)' },
    ],
    template: 'openssl s_client -connect {{domain}}:{{port}} -servername {{domain}} </dev/null 2>/dev/null | openssl x509 -noout -text',
    supportedOS: ['linux', 'macos'],
    supportedShells: ['bash', 'zsh', 'sh'],
    riskLevel: 1,
    authorizationRequired: true,
  };
  registry.registerTemplate(opensslCert);

  // Dig DNS lookup — RISK 0 (passive)
  const digAny: CommandTemplate = {
    id: 'dig.lookup.v1',
    version: 1,
    tool: 'dig',
    operation: 'dns-lookup',
    description: 'Look up DNS records for a domain',
    category: 'recon',
    params: [
      { name: 'domain', kind: 'domain', required: true, description: 'Domain to look up', defaultFrom: 'target.value' },
    ],
    template: 'dig {{domain}} ANY +noall +answer',
    supportedOS: ['linux', 'macos'],
    supportedShells: ['bash', 'zsh', 'sh'],
    riskLevel: 0,
    authorizationRequired: false,
  };
  registry.registerTemplate(digAny);

  // ExifTool metadata — RISK 0 (local file)
  const exifMetadata: CommandTemplate = {
    id: 'exiftool.metadata.v1',
    version: 1,
    tool: 'exiftool',
    operation: 'metadata-extract',
    description: 'Extract metadata from a local file',
    category: 'file-metadata',
    params: [
      { name: 'file', kind: 'path', required: true, description: 'Local file path' },
    ],
    template: 'exiftool {{file}}',
    supportedOS: ['linux', 'windows', 'macos'],
    supportedShells: ['bash', 'zsh', 'powershell', 'sh'],
    riskLevel: 0,
    authorizationRequired: false,
  };
  registry.registerTemplate(exifMetadata);

  // Git status — RISK 0
  const gitStatus: CommandTemplate = {
    id: 'git.status.v1',
    version: 1,
    tool: 'git',
    operation: 'status',
    description: 'Show working tree status',
    category: 'git',
    params: [],
    template: 'git status',
    supportedOS: ['linux', 'windows', 'macos'],
    supportedShells: ['bash', 'zsh', 'sh', 'powershell', 'cmd'],
    riskLevel: 0,
    authorizationRequired: false,
  };
  registry.registerTemplate(gitStatus);

  // Gobuster directory enumeration — RISK 2 (active testing)
  const gobusterDir: CommandTemplate = {
    id: 'gobuster.dir.v1',
    version: 1,
    tool: 'gobuster',
    operation: 'directory-enumeration',
    description: 'Enumerate web directories against an authorized web target',
    category: 'web',
    params: [
      { name: 'url', kind: 'url', required: true, description: 'Base URL of the authorized web target' },
      { name: 'wordlist', kind: 'wordlist', required: true, description: 'Wordlist path (must be a real path detected by the agent)', wordlistDirs: ['/usr/share/wordlists', '/usr/share/seclists', '/opt/wordlists'] },
    ],
    template: 'gobuster dir -u {{url}} -w {{wordlist}}',
    supportedOS: ['linux', 'windows', 'macos'],
    supportedShells: ['bash', 'zsh', 'powershell', 'cmd', 'sh'],
    riskLevel: 2,
    authorizationRequired: true,
    timeoutMs: 300000,
    docsUrl: 'https://github.com/OJ/gobuster',
  };
  registry.registerTemplate(gobusterDir);
  const gobusterFixtures: TemplateFixture[] = [
    {
      templateId: gobusterDir.id,
      inputs: { url: 'https://example.com', wordlist: '/usr/share/wordlists/common.txt' },
      expectedCommand: 'gobuster dir -u https://example.com -w /usr/share/wordlists/common.txt',
    },
  ];
  registry.registerFixtures(gobusterDir.id, gobusterFixtures);
}
