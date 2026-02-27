import { FastifyInstance } from "fastify"
import { z } from "zod"
import pino from "pino"
import crypto from "crypto"
import { exec } from "child_process"
import { promisify } from "util"
import fs from "fs/promises"
import path from "path"
import os from "os"

const execAsync = promisify(exec)
const log = pino({ name: "sandbox", level: "info" })

// Configuration
const config = {
  app: {
    port: parseInt(process.env.PORT || "8084"),
  },
  sandbox: {
    analysisTimeout: parseInt(process.env.SANDBOX_TIMEOUT || "300000"), // 5 min
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || "52428800"), // 50MB
    quarantinePath: process.env.QUARANTINE_PATH || "/tmp/sandbox/quarantine",
    reportsPath: process.env.REPORTS_PATH || "/tmp/sandbox/reports",
  },
}

// Types
interface AnalysisReport {
  id: string
  file_hash: string
  file_name: string
  file_size: number
  file_type: string
  submitted_at: string
  completed_at?: string
  status: "pending" | "analyzing" | "completed" | "failed"
  
  // Static Analysis
  static_analysis?: {
    packer?: string
    imports?: string[]
    strings?: string[]
    yara_matches?: YaraMatch[]
  }
  
  // Dynamic Analysis
  dynamic_analysis?: {
    networkConnections?: NetworkConnection[]
    fileOperations?: FileOperation[]
    registryOperations?: RegistryOperation[]
    processes?: ProcessActivity[]
    droppedFiles?: DroppedFile[]
  }
  
  // Behavior
  behaviors?: Behavior[]
  
  // Verdict
  verdict?: {
    category: "malicious" | "suspicious" | "clean" | "unknown"
    severity: number // 0-100
    confidence: number
    description: string
    mitre_techniques?: string[]
  }
  
  // Screenshots
  screenshots?: string[]
}

interface YaraMatch {
  rule: string
  namespace: string
  matched_strings: string[]
}

interface NetworkConnection {
  protocol: string
  source_ip: string
  source_port: number
  dest_ip: string
  dest_port: number
  direction: "inbound" | "outbound"
}

interface FileOperation {
  operation: "create" | "read" | "write" | "delete"
  path: string
  timestamp: string
}

interface RegistryOperation {
  operation: "create" | "write" | "delete"
  key: string
  value?: string
}

interface ProcessActivity {
  pid: number
  name: string
  command_line?: string
  parent_pid?: number
}

interface DroppedFile {
  path: string
  size: number
  hash: string
}

interface Behavior {
  technique_id: string
  description: string
  severity: number
}

// Sandbox Service
class SandboxService {
  private quarantinePath: string
  private reportsPath: string

  constructor() {
    this.quarantinePath = config.sandbox.quarantinePath
    this.reportsPath = config.sandbox.reportsPath
  }

  async initialize() {
    await fs.mkdir(this.quarantinePath, { recursive: true })
    await fs.mkdir(this.reportsPath, { recursive: true })
    log.info("Sandbox initialized")
  }

  // File hashing
  private async calculateHashes(filePath: string): Promise<Record<string, string>> {
    const { stdout: md5 } = await execAsync(`md5sum "${filePath}" | cut -d' ' -f1`)
    const { stdout: sha1 } = await execAsync(`sha1sum "${filePath}" | cut -d' ' -f1`)
    const { stdout: sha256 } = await execAsync(`sha256sum "${filePath}" | cut -d' ' -f1`)

    return {
      md5: md5.trim(),
      sha1: sha1.trim(),
      sha256: sha256.trim(),
    }
  }

  // File type detection
  private async detectFileType(filePath: string): Promise<string> {
    try {
      const { stdout } = await execAsync(`file -b "${filePath}"`)
      return stdout.trim()
    } catch {
      return "unknown"
    }
  }

  // Static Analysis
  private async performStaticAnalysis(filePath: string, fileHash: string): Promise<AnalysisReport["static_analysis"]> {
    const staticAnalysis: AnalysisReport[" {
      strings: [],
      importsstatic_analysis"] =: [],
    }

    // Extract strings
    try {
      const { stdout } = await execAsync(`strings -n 4 "${filePath}" | head -100`)
      staticAnalysis.strings = stdout.split("\n").filter(s => s.length > 4)
    } catch {
      // Ignore errors
    }

    // Check for known packers
    const packerSignatures = {
      "UPX": "upx",
      "ASPack": "aspack",
      "Themida": "themida",
      "VMProtect": "vmprotect",
    }

    for (const [sig, name] of Object.entries(packerSignatures)) {
      if (staticAnalysis.strings?.some(s => s.includes(sig))) {
        staticAnalysis.packer = name
        break
      }
    }

    // YARA scanning (if rules exist)
    staticAnalysis.yara_matches = await this.runYaraScan(filePath)

    return staticAnalysis
  }

  private async runYaraScan(filePath: string): Promise<YaraMatch[]> {
    const yaraRulesPath = "/etc/sandbox/rules"
    
    try {
      await fs.access(yaraRulesPath)
    } catch {
      // No rules installed
      return []
    }

    try {
      const { stdout } = await execAsync(
        `yarac "${yaraRulesPath}" - 2>/dev/null || echo "no_rules"`
      )
      if (stdout.includes("no_rules")) return []
      
      // Simplified - in production use proper yara
      return []
    } catch {
      return []
    }
  }

  // Dynamic Analysis (simulated - in production use CAPEv2)
  private async performDynamicAnalysis(filePath: string): Promise<AnalysisReport["dynamic_analysis"]> {
    // Simulate dynamic analysis behavior
    // In production, this would run in isolated VM/container
    
    const dynamicAnalysis: AnalysisReport["dynamic_analysis"] = {
      networkConnections: [],
      fileOperations: [],
      processes: [],
      droppedFiles: [],
    }

    // Simulate network connections
    const suspiciousDomains = [
      "evil-c2.malware.com",
      "payload-delivery.net",
    ]

    if (Math.random() > 0.5) {
      dynamicAnalysis.networkConnections?.push({
        protocol: "TCP",
        source_ip: "192.168.1.100",
        source_port: 49152,
        dest_ip: "185.243.115.84",
        dest_port: 443,
        direction: "outbound",
      })
    }

    // Simulate file operations
    dynamicAnalysis.fileOperations?.push({
      operation: "create",
      path: `${os.tmpdir()}/malware_config.dat`,
      timestamp: new Date().toISOString(),
    })

    // Simulate process
    dynamicAnalysis.processes?.push({
      pid: 1234,
      name: "malware.exe",
      command_line: "malware.exe -hidden",
      parent_pid: 1000,
    })

    return dynamicAnalysis
  }

  // Behavior Mapping to MITRE ATT&CK
  private mapToMitre(dynamicAnalysis: AnalysisReport["dynamic_analysis"]): Behavior[] {
    const behaviors: Behavior[] = []

    if (dynamicAnalysis?.networkConnections?.length) {
      behaviors.push({
        technique_id: "T1071",
        description: "Application Layer Protocol - Network connection detected",
        severity: 5,
      })
    }

    if (dynamicAnalysis?.fileOperations?.some(f => f.operation === "create")) {
      behaviors.push({
        technique_id: "T1059",
        description: "Command and Scripting Interpreter - File created",
        severity: 6,
      })
    }

    if (dynamicAnalysis?.droppedFiles?.length) {
      behaviors.push({
        technique_id: "T1056",
        description: "Input Capture - Dropped files detected",
        severity: 7,
      })
    }

    return behaviors
  }

  // Verdict Generation
  private generateVerdict(
    staticAnalysis: AnalysisReport["static_analysis"],
    dynamicAnalysis: AnalysisReport["dynamic_analysis"],
    behaviors: Behavior[]
  ): AnalysisReport["verdict"] {
    let severity = 0
    let confidence = 0
    const mitreTechniques: string[] = []

    // Check YARA matches
    if (staticAnalysis?.yara_matches?.length) {
      severity += 30 * staticAnalysis.yara_matches.length
      confidence += 40
      mitreTechniques.push("T1059")
    }

    // Check suspicious network
    if (dynamicAnalysis?.networkConnections?.length) {
      severity += 25
      confidence += 30
      mitreTechniques.push("T1071")
    }

    // Check dropped files
    if (dynamicAnalysis?.droppedFiles?.length) {
      severity += 20
      confidence += 35
      mitreTechniques.push("T1056")
    }

    // Check packer
    if (staticAnalysis?.packer) {
      severity += 15
      confidence += 25
    }

    // Normalize
    severity = Math.min(severity, 100)
    confidence = Math.min(confidence, 100)

    let category: AnalysisReport["verdict"]["category"]
    if (severity >= 70) category = "malicious"
    else if (severity >= 40) category = "suspicious"
    else if (severity >= 10) category = "unknown"
    else category = "clean"

    return {
      category,
      severity,
      confidence,
      description: this.generateVerdictDescription(category, severity),
      mitre_techniques: mitreTechniques,
    }
  }

  private generateVerdictDescription(category: string, severity: number): string {
    switch (category) {
      case "malicious":
        return `High-risk malware detected (severity: ${severity}). This file exhibits malicious behaviors including potential data exfiltration, process injection, or command & control communication.`
      case "suspicious":
        return `Suspicious activity detected (severity: ${severity}). This file shows behaviors that may indicate malicious intent but requires further analysis.`
      case "unknown":
        return `Unknown risk level (severity: ${severity}). No clear malicious or benign indicators were found. Manual analysis recommended.`
      case "clean":
        return `No malicious indicators detected (severity: ${severity}). This file appears to be benign.`
      default:
        return "Analysis incomplete."
    }
  }

  // Main Analysis Function
  async analyzeFile(fileBuffer: Buffer, fileName: string): Promise<AnalysisReport> {
    const id = crypto.randomUUID()
    const tempPath = path.join(os.tmpdir(), `${id}-${fileName}`)
    
    // Write file to temp
    await fs.writeFile(tempPath, fileBuffer)
    
    const fileSize = fileBuffer.length
    const hashes = await this.calculateHashes(tempPath)
    const fileType = await this.detectFileType(tempPath)

    const report: AnalysisReport = {
      id,
      file_hash: hashes.sha256,
      file_name: fileName,
      file_size: fileSize,
      file_type: fileType,
      submitted_at: new Date().toISOString(),
      status: "analyzing",
    }

    try {
      // Static Analysis
      report.static_analysis = await this.performStaticAnalysis(tempPath, hashes.sha256)

      // Dynamic Analysis
      report.dynamic_analysis = await this.performDynamicAnalysis(tempPath)

      // Behavior Mapping
      report.behaviors = this.mapToMitre(report.dynamic_analysis)

      // Verdict
      report.verdict = this.generateVerdict(
        report.static_analysis,
        report.dynamic_analysis,
        report.behaviors
      )

      report.status = "completed"
      report.completed_at = new Date().toISOString()

      // Quarantine if malicious
      if (report.verdict?.category === "malicious") {
        const quarantinePath = path.join(this.quarantinePath, `${hashes.sha256}-${fileName}`)
        await fs.copyFile(tempPath, quarantinePath)
        log.warn({ hash: hashes.sha256, file: fileName }, "Malware quarantined")
      }

    } catch (error) {
      report.status = "failed"
      log.error({ error, reportId: id }, "Analysis failed")
    } finally {
      // Cleanup temp file
      await fs.unlink(tempPath).catch(() => {})
    }

    // Save report
    await this.saveReport(report)

    return report
  }

  private async saveReport(report: AnalysisReport) {
    const reportPath = path.join(this.reportsPath, `${report.id}.json`)
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2))
  }

  async getReport(id: string): Promise<AnalysisReport | null> {
    try {
      const reportPath = path.join(this.reportsPath, `${id}.json`)
      const data = await fs.readFile(reportPath)
      return JSON.parse(data.toString())
    } catch {
      return null
    }
  }

  async getReportByHash(hash: string): Promise<AnalysisReport[]> {
    const files = await fs.readdir(this.reportsPath)
    const reports: AnalysisReport[] = []

    for (const file of files) {
      if (!file.endsWith(".json")) continue
      
      const data = await fs.readFile(path.join(this.reportsPath, file))
      const report: AnalysisReport = JSON.parse(data.toString())
      
      if (report.file_hash === hash) {
        reports.push(report)
      }
    }

    return reports
  }

  async listReports(limit = 50): Promise<AnalysisReport[]> {
    const files = await fs.readdir(this.reportsPath)
    const reports: AnalysisReport[] = []

    const jsonFiles = files
      .filter(f => f.endsWith(".json"))
      .sort()
      .reverse()
      .slice(0, limit)

    for (const file of jsonFiles) {
      const data = await fs.readFile(path.join(this.reportsPath, file))
      reports.push(JSON.parse(data.toString()))
    }

    return reports
  }
}

// Fastify API
export async function buildApp(sandbox: SandboxService): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify")
  const app = fastify()

  await sandbox.initialize()

  // Routes
  app.get("/health", async () => ({ status: "ok" }))

  // Submit file for analysis
  app.post("/api/v1/sandbox/analyze", async (request, reply) => {
    const data = await request.file()
    
    if (!data) {
      return reply.status(400).send({ error: "No file provided" })
    }

    const buffer = await data.toBuffer()
    const fileName = data.filename

    if (buffer.length > config.sandbox.maxFileSize) {
      return reply.status(413).send({ error: "File too large" })
    }

    const report = await sandbox.analyzeFile(buffer, fileName)
    return report
  })

  // Get report by ID
  app.get<{ Params: { id: string } }>(
    "/api/v1/sandbox/reports/:id",
    async (request) => {
      const report = await sandbox.getReport(request.params.id)
      if (!report) {
        return { error: "Report not found" }
      }
      return report
    }
  )

  // Get report by hash
  app.get<{ Params: { hash: string } }>(
    "/api/v1/sandbox/reports/hash/:hash",
    async (request) => {
      return sandbox.getReportByHash(request.params.hash)
    }
  )

  // List recent reports
  app.get<{ Querystring: { limit?: string } }>(
    "/api/v1/sandbox/reports",
    async (request) => {
      const limit = parseInt(request.query.limit || "50")
      return sandbox.listReports(limit)
    }
  )

  return app
}

// Main
async function main() {
  const sandbox = new SandboxService()

  const app = await buildApp(sandbox)
  await app.listen({ port: config.app.port, host: "0.0.0.0" })

  log.info(`Sandbox API listening on port ${config.app.port}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
