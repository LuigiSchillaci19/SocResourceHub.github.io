import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export interface CategoryTool {
  name: string;
  url: string;
  icon?: string;
}

export interface ToolSection {
  title: string;
  tools: CategoryTool[];
}

export interface CategoryProps {
  title: string;
  icon: string;
  borderColor: string;
  sections: ToolSection[];
}

export const allCategories: CategoryProps[] = [
  {
    title: "Digital Forensics",
    icon: "ri-file-search-line",
    borderColor: "border-destructive",
    sections: [
      {
        title: "Memory Analysis",
        tools: [
          { name: "Volatility", url: "https://volatilityfoundation.org" },
          { name: "Rekall", url: "https://www.rekall-forensic.com" },
          { name: "GRR", url: "https://github.com/google/grr" }
        ]
      },
      {
        title: "Disk Forensics",
        tools: [
          { name: "Autopsy", url: "https://www.sleuthkit.org/autopsy/" },
          { name: "KAPE", url: "https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape" },
          { name: "EZ Tools", url: "https://ericzimmerman.github.io" }
        ]
      },
      {
        title: "Network Forensics",
        tools: [
          { name: "Wireshark", url: "https://www.wireshark.org" },
          { name: "NetworkMiner", url: "https://www.netresec.com/?page=NetworkMiner" },
          { name: "Dshell", url: "https://github.com/USArmyResearchLab/Dshell" }
        ]
      },
      {
        title: "Documentation",
        tools: [
          { 
            name: "Awesome Forensics", 
            url: "https://github.com/cugu/awesome-forensics",
            icon: "ri-book-2-line"
          },
          { 
            name: "SANS DFIR Resources", 
            url: "https://github.com/alphaSeclab/forensics-resources",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Email Analysis",
    icon: "ri-mail-open-line",
    borderColor: "border-warning",
    sections: [
      {
        title: "Phishing Analysis",
        tools: [
          { name: "PhishTool", url: "https://www.phishtool.com" },
          { name: "PhishTank", url: "https://phishtank.org" },
          { name: "URLScan.io", url: "https://urlscan.io" }
        ]
      },
      {
        title: "Email Headers",
        tools: [
          { name: "MXToolbox", url: "https://mxtoolbox.com/EmailHeaders.aspx" },
          { name: "Message Header Analyzer", url: "https://mha.azurewebsites.net" },
          { name: "IPInfo", url: "https://ipinfo.io" }
        ]
      },
      {
        title: "Document Analysis",
        tools: [
          { name: "Malware Analysis Online", url: "https://malwareanalysis.online" },
          { name: "OLEVBA", url: "https://github.com/decalage2/oletools/wiki/olevba" },
          { name: "PDF Examiner", url: "https://www.pdfexaminer.com" }
        ]
      },
      {
        title: "Resources",
        tools: [
          { 
            name: "Email Analysis Workflow", 
            url: "https://www.sans.org/blog/email-analysis-workflow/",
            icon: "ri-book-2-line"
          },
          { 
            name: "Malicious Document Analysis", 
            url: "https://github.com/rshipp/awesome-malware-analysis#documents-and-shellcode",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Threat Hunting",
    icon: "ri-radar-line",
    borderColor: "border-secondary",
    sections: [
      {
        title: "SIEM & Analytics",
        tools: [
          { name: "Elastic SIEM", url: "https://www.elastic.co/security" },
          { name: "Splunk ES", url: "https://www.splunk.com/en_us/cybersecurity.html" },
          { name: "TH Playbook", url: "https://github.com/OTRF/ThreatHunter-Playbook" }
        ]
      },
      {
        title: "SIEM Rule Creation",
        tools: [
          { name: "Sigma Rules", url: "https://github.com/SigmaHQ/sigma" },
          { name: "SOC Prime", url: "https://socprime.com/search-engine" },
          { name: "Elastic Rule Creator", url: "https://github.com/elastic/detection-rules" }
        ]
      },
      {
        title: "Endpoint Analysis",
        tools: [
          { name: "OSQuery", url: "https://www.osquery.io" },
          { name: "MITRE CAR", url: "https://github.com/mitre-attack/car" },
          { name: "Velociraptor", url: "https://docs.velociraptor.app" }
        ]
      },
      {
        title: "Behavioral Analysis",
        tools: [
          { name: "MITRE ATT&CK", url: "https://attack.mitre.org" },
          { name: "Atomic Red Team", url: "https://github.com/redcanaryco/atomic-red-team" },
          { name: "Uncoder.IO", url: "https://uncoder.io" }
        ]
      },
      {
        title: "Documentation",
        tools: [
          { 
            name: "SANS Threat Hunting Guide", 
            url: "https://www.sans.org/blog/a-simplified-approach-to-threat-hunting/",
            icon: "ri-book-2-line"
          },
          { 
            name: "Threat Hunting Rules", 
            url: "https://github.com/ThreatHuntingProject/ThreatHunting",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "IOC Verification",
    icon: "ri-eye-line",
    borderColor: "border-warning",
    sections: [
      {
        title: "File Analysis",
        tools: [
          { name: "VirusTotal", url: "https://www.virustotal.com" },
          { name: "Hybrid Analysis", url: "https://hybrid-analysis.com" },
          { name: "ANY.RUN", url: "https://any.run" }
        ]
      },
      {
        title: "Domain/IP Analysis",
        tools: [
          { name: "AbuseIPDB", url: "https://www.abuseipdb.com" },
          { name: "OTX AlienVault", url: "https://otx.alienvault.com" },
          { name: "URLScan.io", url: "https://urlscan.io" }
        ]
      },
      {
        title: "Threat Intelligence",
        tools: [
          { name: "Talos Intel", url: "https://talosintelligence.com" },
          { name: "ThreatFox", url: "https://threatfox.abuse.ch" },
          { name: "IBM X-Force", url: "https://exchange.xforce.ibmcloud.com" }
        ]
      },
      {
        title: "IOC Tools",
        tools: [
          { 
            name: "LOKI Scanner", 
            url: "https://github.com/Neo23x0/Loki",
            icon: "ri-search-eye-line"
          },
          { 
            name: "MISP Platform", 
            url: "https://github.com/MISP/MISP",
            icon: "ri-bubble-chart-line"
          },
          {
            name: "ThreatConnect",
            url: "https://threatconnect.com",
            icon: "ri-shield-keyhole-line"
          }
        ]
      }
    ]
  },
  {
    title: "Malware Analysis",
    icon: "ri-virus-line",
    borderColor: "border-destructive",
    sections: [
      {
        title: "Static Analysis",
        tools: [
          { name: "DIE", url: "https://github.com/horsicq/Detect-It-Easy" },
          { name: "PEStudio", url: "https://www.winitor.com" },
          { name: "FLARE VM", url: "https://github.com/mandiant/flare-vm" }
        ]
      },
      {
        title: "Dynamic Analysis",
        tools: [
          { name: "Cuckoo", url: "https://github.com/cuckoosandbox/cuckoo" },
          { name: "Triage", url: "https://tria.ge" },
          { name: "Joe Sandbox", url: "https://www.joesandbox.com" }
        ]
      },
      {
        title: "Document Analysis",
        tools: [
          { name: "Oletools", url: "https://github.com/decalage2/oletools" },
          { name: "PDFExaminer", url: "https://www.pdfexaminer.com" },
          { name: "XLMMacroDeobfuscator", url: "https://github.com/DissectMalware/XLMMacroDeobfuscator" }
        ]
      },
      {
        title: "Reverse Engineering",
        tools: [
          { name: "Ghidra", url: "https://ghidra-sre.org" },
          { name: "IDA Pro", url: "https://hex-rays.com/ida-pro" },
          { name: "x64dbg", url: "https://x64dbg.com" }
        ]
      },
      {
        title: "Learning Resources",
        tools: [
          { 
            name: "Awesome Malware Analysis", 
            url: "https://github.com/rshipp/awesome-malware-analysis",
            icon: "ri-book-2-line"
          },
          { 
            name: "Malware Traffic Analysis", 
            url: "https://www.malware-traffic-analysis.net",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Incident Response",
    icon: "ri-fire-line",
    borderColor: "border-success",
    sections: [
      {
        title: "IR Frameworks",
        tools: [
          { name: "IR Playbooks", url: "https://www.incidentresponse.org/playbooks/" },
          { name: "IRM", url: "https://github.com/certsocietegenerale/IRM" },
          { name: "NIST 800-61", url: "https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf" }
        ]
      },
      {
        title: "IR Tools",
        tools: [
          { name: "GRR", url: "https://github.com/google/grr" },
          { name: "The HELK", url: "https://github.com/Cyb3rWard0g/HELK" },
          { name: "DFIR-ORC", url: "https://github.com/dfir-orc/dfir-orc" }
        ]
      },
      {
        title: "Containment & Remediation",
        tools: [
          { name: "Autoruns", url: "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns" },
          { name: "Sysmon", url: "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" },
          { name: "PowerSponse", url: "https://github.com/swisscom/PowerSponse" }
        ]
      },
      {
        title: "Alert Rule Creation",
        tools: [
          { name: "Sigma Rules", url: "https://github.com/SigmaHQ/sigma/tree/master/rules" },
          { name: "Detection Lab", url: "https://github.com/Security-Onion-Solutions/securityonion" },
          { name: "Splunk Security Content", url: "https://github.com/splunk/security_content" }
        ]
      },
      {
        title: "Documentation",
        tools: [
          { 
            name: "Awesome Incident Response", 
            url: "https://github.com/meirwah/awesome-incident-response",
            icon: "ri-book-2-line"
          },
          { 
            name: "SANS Incident Handler's Handbook", 
            url: "https://www.sans.org/white-papers/incident-handlers-handbook/",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Vulnerability Management",
    icon: "ri-shield-check-line",
    borderColor: "border-secondary",
    sections: [
      {
        title: "Vulnerability Scanning",
        tools: [
          { name: "Nessus", url: "https://www.tenable.com/products/nessus" },
          { name: "OpenVAS", url: "https://www.openvas.org" },
          { name: "Qualys", url: "https://www.qualys.com" }
        ]
      },
      {
        title: "Vuln Databases",
        tools: [
          { name: "NVD", url: "https://nvd.nist.gov" },
          { name: "CVE", url: "https://cve.mitre.org" },
          { name: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" }
        ]
      },
      {
        title: "Patch Management",
        tools: [
          { name: "Ivanti", url: "https://www.ivanti.com/products/patch-management" },
          { name: "SCCM", url: "https://learn.microsoft.com/en-us/mem/configmgr/sum/understand/software-updates-introduction" },
          { name: "Patchman", url: "https://patchman.co" }
        ]
      },
      {
        title: "Resources",
        tools: [
          { 
            name: "OWASP Top 10", 
            url: "https://owasp.org/www-project-top-ten/",
            icon: "ri-book-2-line"
          },
          { 
            name: "SANS VM Process", 
            url: "https://www.sans.org/blog/vulnerability-management-process-overview/",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "SIEM Rules & Alerting",
    icon: "ri-alarm-warning-line",
    borderColor: "border-warning",
    sections: [
      {
        title: "Rule Creation",
        tools: [
          { name: "Sigma Rules", url: "https://github.com/SigmaHQ/sigma" },
          { name: "SOC Prime", url: "https://socprime.com/search-engine" },
          { name: "Uncoder.IO", url: "https://uncoder.io" }
        ]
      },
      {
        title: "SIEM Platforms",
        tools: [
          { name: "Splunk", url: "https://www.splunk.com/en_us/download/splunk-enterprise.html" },
          { name: "Elastic SIEM", url: "https://www.elastic.co/security" },
          { name: "Graylog", url: "https://www.graylog.org" }
        ]
      },
      {
        title: "SOAR Integrations",
        tools: [
          { name: "Tines", url: "https://www.tines.com" },
          { name: "Cortex XSOAR", url: "https://www.paloaltonetworks.com/cortex/cortex-xsoar" },
          { name: "TheHive", url: "https://thehive-project.org" }
        ]
      },
      {
        title: "Documentation",
        tools: [
          { 
            name: "Sigma Wiki", 
            url: "https://github.com/SigmaHQ/sigma/wiki",
            icon: "ri-book-2-line"
          },
          { 
            name: "Detection Engineering", 
            url: "https://github.com/infosecB/awesome-detection-engineering",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Cloud Security",
    icon: "ri-cloud-line",
    borderColor: "border-primary",
    sections: [
      {
        title: "AWS Security",
        tools: [
          { name: "AWS GuardDuty", url: "https://aws.amazon.com/guardduty/" },
          { name: "Prowler", url: "https://github.com/prowler-cloud/prowler" },
          { name: "ScoutSuite", url: "https://github.com/nccgroup/ScoutSuite" }
        ]
      },
      {
        title: "Azure Security",
        tools: [
          { name: "Azure Sentinel", url: "https://azure.microsoft.com/en-us/products/microsoft-sentinel" },
          { name: "Defender for Cloud", url: "https://azure.microsoft.com/en-us/products/defender-for-cloud" },
          { name: "AzSK", url: "https://github.com/azsk/DevOpsKit" }
        ]
      },
      {
        title: "GCP Security",
        tools: [
          { name: "Security Command Center", url: "https://cloud.google.com/security-command-center" },
          { name: "GCP Security Scanner", url: "https://cloud.google.com/security-scanner" },
          { name: "Forseti Security", url: "https://github.com/forseti-security/forseti-security" }
        ]
      },
      {
        title: "Multi-Cloud Tools",
        tools: [
          { name: "CloudSploit", url: "https://github.com/aquasecurity/cloudsploit" },
          { name: "Prisma Cloud", url: "https://www.paloaltonetworks.com/prisma/cloud" },
          { name: "Cloud Custodian", url: "https://cloudcustodian.io" }
        ]
      }
    ]
  },
  {
    title: "Threat Intelligence",
    icon: "ri-spy-line",
    borderColor: "border-secondary",
    sections: [
      {
        title: "Intelligence Platforms",
        tools: [
          { name: "MISP", url: "https://www.misp-project.org" },
          { name: "OpenCTI", url: "https://www.opencti.io" },
          { name: "ThreatConnect", url: "https://threatconnect.com" }
        ]
      },
      {
        title: "Feeds & Sources",
        tools: [
          { name: "AlienVault OTX", url: "https://otx.alienvault.com" },
          { name: "ThreatFox", url: "https://threatfox.abuse.ch" },
          { name: "VirusTotal", url: "https://www.virustotal.com/gui/intelligence-overview" }
        ]
      },
      {
        title: "Analysis Tools",
        tools: [
          { name: "Maltego", url: "https://www.maltego.com" },
          { name: "Yara", url: "https://github.com/VirusTotal/yara" },
          { name: "CyberChef", url: "https://gchq.github.io/CyberChef" }
        ]
      },
      {
        title: "Documentation",
        tools: [
          { 
            name: "CTI Frameworks", 
            url: "https://github.com/hslatman/awesome-threat-intelligence",
            icon: "ri-book-2-line"
          },
          { 
            name: "SANS CTI Resources", 
            url: "https://www.sans.org/blog/who-s-using-cyberthreat-intelligence-and-how/",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Security Automation",
    icon: "ri-robot-line",
    borderColor: "border-success",
    sections: [
      {
        title: "Automation Platforms",
        tools: [
          { name: "Tines", url: "https://www.tines.io" },
          { name: "Shuffle", url: "https://github.com/Shuffle/Shuffle" },
          { name: "n8n", url: "https://n8n.io" }
        ]
      },
      {
        title: "Security Orchestration",
        tools: [
          { name: "Cortex XSOAR", url: "https://www.paloaltonetworks.com/cortex/cortex-xsoar" },
          { name: "Swimlane", url: "https://swimlane.com" },
          { name: "TheHive", url: "https://thehive-project.org" }
        ]
      },
      {
        title: "DevSecOps",
        tools: [
          { name: "Jenkins", url: "https://www.jenkins.io" },
          { name: "GitHub Actions", url: "https://github.com/features/actions" },
          { name: "GitLab CI/CD", url: "https://docs.gitlab.com/ee/ci" }
        ]
      },
      {
        title: "Playbooks & Guides",
        tools: [
          { 
            name: "SOC Automation Guide", 
            url: "https://github.com/austinsonger/SOC-Automation",
            icon: "ri-book-2-line"
          },
          { 
            name: "Awesome Security Automation", 
            url: "https://github.com/charlescsr/awesome-security-automation",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Network Security Monitoring",
    icon: "ri-wifi-line",
    borderColor: "border-destructive",
    sections: [
      {
        title: "Network IDS/IPS",
        tools: [
          { name: "Suricata", url: "https://suricata.io" },
          { name: "Snort", url: "https://www.snort.org" },
          { name: "Zeek (Bro)", url: "https://zeek.org" }
        ]
      },
      {
        title: "Network Analysis",
        tools: [
          { name: "Wireshark", url: "https://www.wireshark.org" },
          { name: "NetworkMiner", url: "https://www.netresec.com/?page=NetworkMiner" },
          { name: "Arkime (Moloch)", url: "https://arkime.com" }
        ]
      },
      {
        title: "Packet Capture",
        tools: [
          { name: "tcpdump", url: "https://www.tcpdump.org" },
          { name: "TShark", url: "https://www.wireshark.org/docs/man-pages/tshark.html" },
          { name: "PcapXray", url: "https://github.com/Srinivas11789/PcapXray" }
        ]
      },
      {
        title: "Documentation",
        tools: [
          { 
            name: "NSM Resources", 
            url: "https://github.com/0x4D31/awesome-network-security",
            icon: "ri-book-2-line"
          },
          { 
            name: "SANS NSM Guide", 
            url: "https://www.sans.org/white-papers/network-security-monitoring-101/",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  },
  {
    title: "Active Defense & Deception",
    icon: "ri-game-line",
    borderColor: "border-secondary",
    sections: [
      {
        title: "Honeypots",
        tools: [
          { name: "T-Pot", url: "https://github.com/telekom-security/tpotce" },
          { name: "Modern Honey Network", url: "https://github.com/pwnlandia/mhn" },
          { name: "HoneyDrive", url: "https://bruteforcelab.com/honeydrive" }
        ]
      },
      {
        title: "Threat Hunting Tools",
        tools: [
          { name: "ELK Stack", url: "https://www.elastic.co/elastic-stack" },
          { name: "HELK", url: "https://github.com/Cyb3rWard0g/HELK" },
          { name: "Hayabusa", url: "https://github.com/Yamato-Security/hayabusa" }
        ]
      },
      {
        title: "Active Defense",
        tools: [
          { name: "Artillery", url: "https://github.com/BinaryDefense/artillery" },
          { name: "Canarytokens", url: "https://canarytokens.org" },
          { name: "OpenCanary", url: "https://github.com/thinkst/opencanary" }
        ]
      },
      {
        title: "Resources",
        tools: [
          { 
            name: "Active Defense Guide", 
            url: "https://www.sans.org/white-papers/defensive-deception-101/",
            icon: "ri-book-2-line"
          },
          { 
            name: "MITRE Engage", 
            url: "https://engage.mitre.org",
            icon: "ri-book-2-line"
          }
        ]
      }
    ]
  }
];
