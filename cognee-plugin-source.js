import fs from "node:fs/promises";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------
const DEFAULT_BASE_URL = process.env.COGNEE_BASE_URL || "http://localhost:8000";
const DEFAULT_DATASET_NAME = "openclaw";
const DEFAULT_SEARCH_TYPE = "GRAPH_COMPLETION";
const DEFAULT_MAX_RESULTS = 6;
const DEFAULT_MIN_SCORE = 0;
const DEFAULT_MAX_TOKENS = 512;
const DEFAULT_AUTO_RECALL = true; // Enabled: sleep cycle produces quality memory data for retrieval
const DEFAULT_AUTO_INDEX = true;
const DEFAULT_AUTO_COGNIFY = true;
const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;
const STATE_PATH = join(homedir(), ".openclaw", "memory", "cognee", "datasets.json");
const SYNC_INDEX_PATH = join(homedir(), ".openclaw", "memory", "cognee", "sync-index.json");
/** Glob patterns for memory files, relative to workspace root. */
const MEMORY_FILE_PATTERNS = ["MEMORY.md", "memory.md", "memory"];
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function resolveEnvVars(value) {
    return value.replace(/\$\{([^}]+)\}/g, (_, envVar) => {
        const envValue = process.env[envVar];
        if (!envValue) {
            throw new Error(`Environment variable ${envVar} is not set`);
        }
        return envValue;
    });
}
function hashText(value) {
    return createHash("sha256").update(value).digest("hex");
}
function resolveConfig(rawConfig) {
    const raw = rawConfig && typeof rawConfig === "object" && !Array.isArray(rawConfig)
        ? rawConfig
        : {};
    const baseUrl = raw.baseUrl?.trim() || DEFAULT_BASE_URL;
    const datasetName = raw.datasetName?.trim() || DEFAULT_DATASET_NAME;
    const searchType = raw.searchType || DEFAULT_SEARCH_TYPE;
    const maxResults = typeof raw.maxResults === "number" ? raw.maxResults : DEFAULT_MAX_RESULTS;
    const minScore = typeof raw.minScore === "number" ? raw.minScore : DEFAULT_MIN_SCORE;
    const maxTokens = typeof raw.maxTokens === "number" ? raw.maxTokens : DEFAULT_MAX_TOKENS;
    const autoRecall = typeof raw.autoRecall === "boolean" ? raw.autoRecall : DEFAULT_AUTO_RECALL;
    const autoIndex = typeof raw.autoIndex === "boolean" ? raw.autoIndex : DEFAULT_AUTO_INDEX;
    const autoCognify = typeof raw.autoCognify === "boolean" ? raw.autoCognify : DEFAULT_AUTO_COGNIFY;
    const requestTimeoutMs = typeof raw.requestTimeoutMs === "number" ? raw.requestTimeoutMs : DEFAULT_REQUEST_TIMEOUT_MS;
    const apiKey = raw.apiKey && raw.apiKey.length > 0
        ? resolveEnvVars(raw.apiKey)
        : process.env.COGNEE_API_KEY || "";
    return {
        baseUrl,
        apiKey,
        datasetName,
        searchType,
        maxResults,
        minScore,
        maxTokens,
        autoRecall,
        autoIndex,
        autoCognify,
        requestTimeoutMs,
    };
}
// ---------------------------------------------------------------------------
// Persistence — dataset state & sync index
// ---------------------------------------------------------------------------
async function loadDatasetState() {
    try {
        const raw = await fs.readFile(STATE_PATH, "utf-8");
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== "object")
            return {};
        return parsed;
    }
    catch (error) {
        if (error.code === "ENOENT")
            return {};
        throw error;
    }
}
async function saveDatasetState(state) {
    await fs.mkdir(dirname(STATE_PATH), { recursive: true });
    await fs.writeFile(STATE_PATH, JSON.stringify(state, null, 2), "utf-8");
}
async function loadSyncIndex() {
    try {
        const raw = await fs.readFile(SYNC_INDEX_PATH, "utf-8");
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== "object") {
            return { entries: {} };
        }
        const record = parsed;
        record.entries ??= {};
        return record;
    }
    catch (error) {
        if (error.code === "ENOENT") {
            return { entries: {} };
        }
        throw error;
    }
}
async function saveSyncIndex(state) {
    await fs.mkdir(dirname(SYNC_INDEX_PATH), { recursive: true });
    await fs.writeFile(SYNC_INDEX_PATH, JSON.stringify(state, null, 2), "utf-8");
}
// ---------------------------------------------------------------------------
// File collection — scan workspace for memory markdown files
// ---------------------------------------------------------------------------
async function collectMemoryFiles(workspaceDir) {
    const files = [];
    for (const pattern of MEMORY_FILE_PATTERNS) {
        const target = resolve(workspaceDir, pattern);
        try {
            const stat = await fs.stat(target);
            if (stat.isFile() && target.endsWith(".md")) {
                const content = await fs.readFile(target, "utf-8");
                files.push({
                    path: relative(workspaceDir, target),
                    absPath: target,
                    content,
                    hash: hashText(content),
                });
            }
            else if (stat.isDirectory()) {
                // Recursively scan the memory/ directory for .md files
                const entries = await scanDir(target, workspaceDir);
                files.push(...entries);
            }
        }
        catch (error) {
            if (error.code !== "ENOENT") {
                throw error;
            }
            // File/dir doesn't exist — skip silently
        }
    }
    return files;
}
async function scanDir(dir, workspaceDir) {
    const files = [];
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
        const absPath = join(dir, entry.name);
        if (entry.isDirectory()) {
            const nested = await scanDir(absPath, workspaceDir);
            files.push(...nested);
        }
        else if (entry.isFile() && entry.name.endsWith(".md")) {
            const content = await fs.readFile(absPath, "utf-8");
            files.push({
                path: relative(workspaceDir, absPath),
                absPath,
                content,
                hash: hashText(content),
            });
        }
    }
    return files;
}
// ---------------------------------------------------------------------------
// Cognee HTTP client
// ---------------------------------------------------------------------------
class CogneeClient {
    baseUrl;
    apiKey;
    timeoutMs;
    constructor(baseUrl, apiKey, timeoutMs = 30_000) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.timeoutMs = timeoutMs;
    }
    buildHeaders() {
        if (!this.apiKey)
            return {};
        return {
            Authorization: `Bearer ${this.apiKey}`,
            "X-Api-Key": this.apiKey,
        };
    }
    async fetchJson(path, init, timeoutMs = this.timeoutMs) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const response = await fetch(`${this.baseUrl}${path}`, {
                ...init,
                signal: controller.signal,
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Cognee request failed (${response.status}): ${errorText}`);
            }
            return (await response.json());
        }
        finally {
            clearTimeout(timeout);
        }
    }
    async add(params) {
        const formData = new FormData();
        formData.append("data", new Blob([params.data], { type: "text/plain" }), "openclaw-memory.txt");
        formData.append("datasetName", params.datasetName);
        if (params.datasetId) {
            formData.append("datasetId", params.datasetId);
        }
        const data = await this.fetchJson("/api/v1/add", {
            method: "POST",
            headers: this.buildHeaders(),
            body: formData,
        });
        const dataId = this.extractDataId(data.data_id ?? data.data_ingestion_info);
        if (!dataId) {
            console.warn("memory-cognee: add response missing data_id", JSON.stringify({
                keys: Object.keys(data),
                data_id: data.data_id ?? null,
                data_ingestion_info: data.data_ingestion_info ?? null,
            }, null, 2));
        }
        return {
            datasetId: data.dataset_id,
            datasetName: data.dataset_name,
            dataId,
        };
    }
    async update(params) {
        const query = new URLSearchParams({
            data_id: params.dataId,
            dataset_id: params.datasetId,
        });
        const formData = new FormData();
        formData.append("data", new Blob([params.data], { type: "text/plain" }), "openclaw-memory.txt");
        const data = await this.fetchJson(`/api/v1/update?${query.toString()}`, {
            method: "PATCH",
            headers: this.buildHeaders(),
            body: formData,
        });
        return {
            datasetId: data.dataset_id,
            datasetName: data.dataset_name,
            dataId: this.extractDataId(data.data_id ?? data.data_ingestion_info),
        };
    }
    async cognify(params = {}) {
        return this.fetchJson("/api/v1/cognify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...this.buildHeaders(),
            },
            body: JSON.stringify({ datasetIds: params.datasetIds }),
        });
    }
    /**
     * Run Graphiti's temporal awareness pipeline on the specified datasets.
     * This builds a bi-temporal knowledge graph in Neo4j and bridges the
     * resulting nodes into Cognee's vector store for unified search.
     */
    async graphitiCognify(params = {}) {
        return this.fetchJson("/api/v1/graphiti/cognify", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...this.buildHeaders(),
            },
            body: JSON.stringify({ dataset_ids: params.datasetIds }),
        });
    }
    async search(params) {
        const data = await this.fetchJson("/api/v1/search", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...this.buildHeaders(),
            },
            body: JSON.stringify({
                query: params.queryText,
                searchType: params.searchType,
                datasetIds: params.datasetIds,
                max_tokens: params.maxTokens,
            }),
        });
        return this.normalizeSearchResults(data);
    }
    /**
     * Normalize Cognee search response to consistent format.
     * Cognee returns a direct array of strings: ["answer text here"]
     * We convert to: [{ id, text, score }]
     */
    normalizeSearchResults(data) {
        // Handle direct array (Cognee's actual format)
        if (Array.isArray(data)) {
            return data.map((item, index) => {
                if (typeof item === "string") {
                    return { id: `result-${index}`, text: item, score: 1 };
                }
                if (item && typeof item === "object") {
                    const record = item;
                    return {
                        id: typeof record.id === "string" ? record.id : `result-${index}`,
                        text: typeof record.text === "string" ? record.text : JSON.stringify(record),
                        score: typeof record.score === "number" ? record.score : 1,
                        metadata: record.metadata,
                    };
                }
                return { id: `result-${index}`, text: String(item), score: 1 };
            });
        }
        // Handle wrapped format { results: [...] }
        if (data && typeof data === "object" && "results" in data) {
            return this.normalizeSearchResults(data.results);
        }
        return [];
    }
    extractDataId(value) {
        if (!value)
            return undefined;
        if (typeof value === "string")
            return value;
        if (Array.isArray(value)) {
            for (const entry of value) {
                const id = this.extractDataId(entry);
                if (id)
                    return id;
            }
            return undefined;
        }
        if (typeof value !== "object")
            return undefined;
        const record = value;
        if (typeof record.data_id === "string")
            return record.data_id;
        return this.extractDataId(record.data_ingestion_info);
    }
    async listDatasets() {
        return this.fetchJson("/api/v1/datasets", {
            method: "GET",
            headers: this.buildHeaders(),
        });
    }
    async deleteData(params = {}) {
        const query = new URLSearchParams();
        if (params.datasetId) query.set("dataset_id", params.datasetId);
        const qs = query.toString();
        return this.fetchJson(`/api/v1/delete${qs ? `?${qs}` : ""}`, {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json",
                ...this.buildHeaders(),
            },
        });
    }
}
// ---------------------------------------------------------------------------
// Unified sync logic
//
// For each memory file:
//   - New file (no sync index entry)        → add + cognify
//   - Changed file with dataId              → update (no re-cognify)
//   - Changed file without dataId           → add + cognify
//   - Unchanged file                        → skip
//
// Matches clawdbot cognee-provider.ts syncFiles() (lines 422-513).
// ---------------------------------------------------------------------------
async function syncFiles(client, files, syncIndex, cfg, logger) {
    const result = { added: 0, updated: 0, skipped: 0, errors: 0 };
    let datasetId = syncIndex.datasetId;
    let needsCognify = false;
    for (const file of files) {
        const existing = syncIndex.entries[file.path];
        // Skip unchanged files
        if (existing && existing.hash === file.hash) {
            result.skipped++;
            continue;
        }
        const dataWithMetadata = `# ${file.path}\n\n${file.content}\n\n---\nMetadata: ${JSON.stringify({ path: file.path, source: "memory" })}`;
        try {
            // Changed file with prior dataId → try update first
            if (existing?.dataId && datasetId) {
                try {
                    await client.update({
                        dataId: existing.dataId,
                        datasetId,
                        data: dataWithMetadata,
                    });
                    syncIndex.entries[file.path] = { hash: file.hash, dataId: existing.dataId };
                    syncIndex.datasetId = datasetId;
                    syncIndex.datasetName = cfg.datasetName;
                    syncIndex.needsCognify = true;
                    result.updated++;
                    logger.info?.(`memory-cognee: updated ${file.path}`);
                    continue; // Success, move to next file
                }
                catch (updateError) {
                    // If update fails (404/409 - document not found), fall back to add
                    const errorMsg = updateError instanceof Error ? updateError.message : String(updateError);
                    if (errorMsg.includes("404") || errorMsg.includes("409") || errorMsg.includes("not found")) {
                        logger.info?.(`memory-cognee: update failed for ${file.path}, falling back to add`);
                        // Clear the stale dataId and fall through to add
                        delete existing.dataId;
                    }
                    else {
                        throw updateError; // Re-throw other errors
                    }
                }
            }
            // New file, or changed file without dataId, or update failed → add
            const response = await client.add({
                data: dataWithMetadata,
                datasetName: cfg.datasetName,
                datasetId,
            });
            if (response.datasetId && response.datasetId !== datasetId) {
                datasetId = response.datasetId;
                // Persist dataset ID mapping
                const state = await loadDatasetState();
                state[cfg.datasetName] = response.datasetId;
                await saveDatasetState(state);
            }
            syncIndex.entries[file.path] = {
                hash: file.hash,
                dataId: response.dataId,
            };
            syncIndex.datasetId = datasetId;
            syncIndex.datasetName = cfg.datasetName;
            syncIndex.needsCognify = true;
            needsCognify = true;
            result.added++;
            logger.info?.(`memory-cognee: added ${file.path}`);
        }
        catch (error) {
            result.errors++;
            logger.warn?.(`memory-cognee: failed to sync ${file.path}: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    // Cognify after adds (new data needs graph building)
    if (needsCognify && cfg.autoCognify && datasetId) {
        try {
            await client.cognify({ datasetIds: [datasetId] });
            syncIndex.needsCognify = false;
            logger.info?.("memory-cognee: cognify completed");
            // Run Graphiti temporal awareness pipeline after standard cognify.
            // This builds bi-temporal episodic nodes in Neo4j and bridges them
            // into Cognee's vector store for unified graph traversal.
            try {
                const graphitiResult = await client.graphitiCognify({ datasetIds: [datasetId] });
                if (graphitiResult?.success) {
                    logger.info?.(`memory-cognee: graphiti cognify completed (${graphitiResult.episodes_added} episodes)`);
                }
                else {
                    logger.warn?.(`memory-cognee: graphiti cognify returned: ${graphitiResult?.message || "unknown"}`);
                }
            }
            catch (graphitiError) {
                // Non-fatal: Graphiti is an enhancement, not a requirement
                logger.warn?.(`memory-cognee: graphiti cognify failed (non-fatal): ${graphitiError instanceof Error ? graphitiError.message : String(graphitiError)}`);
            }
        }
        catch (error) {
            logger.warn?.(`memory-cognee: cognify failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    // Save sync index to disk
    await saveSyncIndex(syncIndex);
    return { ...result, datasetId };
}
// ---------------------------------------------------------------------------
// Plugin registration
// ---------------------------------------------------------------------------
const memoryCogneePlugin = {
    id: "memory-cognee",
    name: "Memory (Cognee)",
    description: "Cognee-backed memory: indexes workspace memory files, auto-recalls before agent runs",
    kind: "memory",
    register(api) {
        const cfg = resolveConfig(api.pluginConfig);
        const client = new CogneeClient(cfg.baseUrl, cfg.apiKey, cfg.requestTimeoutMs);
        let datasetId;
        let syncIndex = { entries: {} };
        let syncIndexReady = false;
        let resolvedWorkspaceDir; // Set by service/CLI, used by hooks
        // Load persisted state on startup
        const stateReady = Promise.all([
            loadDatasetState()
                .then((state) => {
                datasetId = state[cfg.datasetName];
            })
                .catch((error) => {
                api.logger.warn?.(`memory-cognee: failed to load dataset state: ${String(error)}`);
            }),
            loadSyncIndex()
                .then((state) => {
                syncIndex = state;
                syncIndexReady = true;
                if (!datasetId && state.datasetId && state.datasetName === cfg.datasetName) {
                    datasetId = state.datasetId;
                }
            })
                .catch((error) => {
                api.logger.warn?.(`memory-cognee: failed to load sync index: ${String(error)}`);
            }),
        ]);
        // Helper: run sync with a given workspace dir
        async function runSync(workspaceDir, logger) {
            await stateReady;
            const files = await collectMemoryFiles(workspaceDir);
            if (files.length === 0) {
                logger.info?.("memory-cognee: no memory files found");
                return { added: 0, updated: 0, skipped: 0, errors: 0 };
            }
            logger.info?.(`memory-cognee: found ${files.length} memory file(s), syncing...`);
            const result = await syncFiles(client, files, syncIndex, cfg, logger);
            if (result.datasetId) {
                datasetId = result.datasetId;
            }
            return result;
        }
        // ------------------------------------------------------------------
        // Tool: cognee_search — on-demand memory search
        // ------------------------------------------------------------------
        api.registerTool({
            name: "cognee_search",
            description: "Search long-term memory and knowledge base for relevant context. Use when you need to recall past conversations, stored knowledge, or specific topics.",
            parameters: {
                type: "object",
                properties: {
                    query: {
                        type: "string",
                        description: "The search query describing what you want to recall",
                    },
                    searchType: {
                        type: "string",
                        description: "Search strategy. GRAPH_COMPLETION (default, LLM + graph context), TEMPORAL (time-aware), CHUNKS (fast vector), CHUNKS_LEXICAL (keyword matching), SUMMARIES (hierarchical), RAG_COMPLETION (classic RAG), GRAPH_SUMMARY_COMPLETION (graph + summarization), GRAPH_COMPLETION_COT (chain-of-thought), GRAPH_COMPLETION_CONTEXT_EXTENSION (broader context), TRIPLET_COMPLETION (subject-predicate-object), NATURAL_LANGUAGE (NL graph search), CYPHER (raw graph query), FEELING_LUCKY (auto-select), CODING_RULES (code rules)",
                        enum: ["GRAPH_COMPLETION", "TEMPORAL", "CHUNKS", "CHUNKS_LEXICAL", "SUMMARIES", "RAG_COMPLETION", "GRAPH_SUMMARY_COMPLETION", "GRAPH_COMPLETION_COT", "GRAPH_COMPLETION_CONTEXT_EXTENSION", "TRIPLET_COMPLETION", "NATURAL_LANGUAGE", "CYPHER", "FEELING_LUCKY", "CODING_RULES"],
                    },
                },
                required: ["query"],
            },
            async execute(_id, params) {
                await stateReady;
                const query = typeof params.query === "string" ? params.query.trim() : "";
                if (!query) {
                    return {
                        content: [{ type: "text", text: "Error: query parameter is required" }],
                        details: { error: "missing query" },
                    };
                }
                if (!datasetId) {
                    return {
                        content: [{ type: "text", text: "No memory dataset available. Index memory files first with `openclaw cognee index`." }],
                        details: { error: "no dataset" },
                    };
                }
                const searchType = typeof params.searchType === "string" ? params.searchType : cfg.searchType;
                try {
                    const results = await client.search({
                        queryText: query,
                        searchType,
                        datasetIds: [datasetId],
                        maxTokens: cfg.maxTokens,
                    });
                    const filtered = results
                        .filter((r) => r.score >= cfg.minScore)
                        .slice(0, cfg.maxResults);
                    if (filtered.length === 0) {
                        return {
                            content: [{ type: "text", text: "No relevant memories found." }],
                            details: { resultCount: 0 },
                        };
                    }
                    const payload = filtered.map((r) => ({
                        score: r.score,
                        text: r.text,
                        ...(r.metadata ? { metadata: r.metadata } : {}),
                    }));
                    return {
                        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
                        details: { resultCount: filtered.length },
                    };
                } catch (error) {
                    api.logger.warn?.(`memory-cognee: tool search failed: ${String(error)}`);
                    return {
                        content: [{ type: "text", text: `Memory search failed: ${String(error)}` }],
                        details: { error: String(error) },
                    };
                }
            },
        });
        // ------------------------------------------------------------------
        // Tool: cognee_datasets — list available knowledge datasets
        // ------------------------------------------------------------------
        api.registerTool({
            name: "cognee_datasets",
            description: "List available Cognee knowledge datasets. Use to discover what knowledge collections exist before searching or deleting.",
            parameters: {
                type: "object",
                properties: {},
            },
            async execute() {
                try {
                    const datasets = await client.listDatasets();
                    return {
                        content: [{ type: "text", text: JSON.stringify(datasets, null, 2) }],
                        details: { datasetCount: Array.isArray(datasets) ? datasets.length : 0 },
                    };
                } catch (error) {
                    api.logger.warn?.(`memory-cognee: list datasets failed: ${String(error)}`);
                    return {
                        content: [{ type: "text", text: `Failed to list datasets: ${String(error)}` }],
                        details: { error: String(error) },
                    };
                }
            },
        });
        // ------------------------------------------------------------------
        // Tool: cognee_delete — delete data from knowledge base
        // ------------------------------------------------------------------
        api.registerTool({
            name: "cognee_delete",
            description: "Delete data from the Cognee knowledge base. Use when asked to forget or remove specific knowledge. Can delete an entire dataset.",
            parameters: {
                type: "object",
                properties: {
                    datasetId: {
                        type: "string",
                        description: "ID of the dataset to delete. Use cognee_datasets to find available dataset IDs.",
                    },
                },
            },
            async execute(_id, params) {
                const dsId = typeof params.datasetId === "string" ? params.datasetId.trim() : undefined;
                try {
                    const result = await client.deleteData({ datasetId: dsId });
                    if (dsId === datasetId) {
                        datasetId = undefined;
                    }
                    return {
                        content: [{ type: "text", text: `Data deleted successfully.\n${JSON.stringify(result, null, 2)}` }],
                        details: result,
                    };
                } catch (error) {
                    api.logger.warn?.(`memory-cognee: delete failed: ${String(error)}`);
                    return {
                        content: [{ type: "text", text: `Delete failed: ${String(error)}` }],
                        details: { error: String(error) },
                    };
                }
            },
        });
        // ------------------------------------------------------------------
        // Tool: cognee_cognify — manually trigger knowledge graph rebuild
        // ------------------------------------------------------------------
        api.registerTool({
            name: "cognee_cognify",
            description: "Trigger Cognee to rebuild the knowledge graph from ingested data. Run this after memory files have been updated to make changes searchable. Cognify extracts entities, relationships, and temporal links from raw data. Skips processing if no data has changed since the last cognify.",
            parameters: {
                type: "object",
                properties: {
                    datasetId: {
                        type: "string",
                        description: "Optional dataset ID to cognify. If omitted, uses the current active dataset. Use cognee_datasets to find available dataset IDs.",
                    },
                    force: {
                        type: "boolean",
                        description: "Force cognify even if no changes have been detected since the last run (default: false).",
                    },
                },
            },
            async execute(_id, params) {
                await stateReady;
                const dsId = typeof params.datasetId === "string" ? params.datasetId.trim() : datasetId;
                if (!dsId) {
                    return {
                        content: [{ type: "text", text: "No dataset available. Add data first or specify a datasetId." }],
                        details: { error: "no dataset" },
                    };
                }
                const force = params.force === true;
                if (!force && syncIndex.needsCognify === false) {
                    return {
                        content: [{ type: "text", text: "Knowledge graph is up to date — no changes since last cognify. Use force: true to rebuild anyway." }],
                        details: { skipped: true },
                    };
                }
                // Sync any changed memory files before cognifying
                const workspaceDir = resolvedWorkspaceDir || process.cwd();
                try {
                    const files = await collectMemoryFiles(workspaceDir);
                    const changedFiles = files.filter((f) => {
                        const existing = syncIndex.entries[f.path];
                        return !existing || existing.hash !== f.hash;
                    });
                    if (changedFiles.length > 0) {
                        api.logger.info?.(`memory-cognee: cognify pre-sync: ${changedFiles.length} changed file(s)`);
                        const syncResult = await syncFiles(client, changedFiles, syncIndex, cfg, api.logger);
                        if (syncResult.datasetId) {
                            datasetId = syncResult.datasetId;
                        }
                        api.logger.info?.(`memory-cognee: cognify pre-sync: ${syncResult.added} added, ${syncResult.updated} updated`);
                    }
                } catch (syncErr) {
                    api.logger.warn?.(`memory-cognee: cognify pre-sync failed: ${String(syncErr)}`);
                }
                try {
                    const result = await client.cognify({ datasetIds: [dsId] });
                    syncIndex.needsCognify = false;
                    await saveSyncIndex(syncIndex);
                    return {
                        content: [{ type: "text", text: `Cognify completed successfully for dataset ${dsId}.\n${JSON.stringify(result, null, 2)}` }],
                        details: result,
                    };
                } catch (error) {
                    api.logger.warn?.(`memory-cognee: cognify failed: ${String(error)}`);
                    return {
                        content: [{ type: "text", text: `Cognify failed: ${String(error)}` }],
                        details: { error: String(error) },
                    };
                }
            },
        });
        // ------------------------------------------------------------------
        // CLI: openclaw cognee index / openclaw cognee status
        // ------------------------------------------------------------------
        api.registerCli((ctx) => {
            const cognee = ctx.program.command("cognee").description("Cognee memory management");
            const resolvedWorkspaceDir = ctx.workspaceDir || process.cwd();
            cognee
                .command("index")
                .description("Sync memory files to Cognee (add new, update changed, skip unchanged)")
                .action(async () => {
                const result = await runSync(resolvedWorkspaceDir, ctx.logger);
                const summary = `Sync complete: ${result.added} added, ${result.updated} updated, ${result.skipped} unchanged, ${result.errors} errors`;
                ctx.logger.info?.(summary);
                console.log(summary);
            });
            cognee
                .command("status")
                .description("Show Cognee sync state (files indexed, dataset info)")
                .action(async () => {
                await stateReady;
                const entryCount = Object.keys(syncIndex.entries).length;
                const entriesWithDataId = Object.values(syncIndex.entries).filter((e) => e.dataId).length;
                const files = await collectMemoryFiles(resolvedWorkspaceDir);
                let dirty = 0;
                let newCount = 0;
                for (const file of files) {
                    const existing = syncIndex.entries[file.path];
                    if (!existing) {
                        newCount++;
                    }
                    else if (existing.hash !== file.hash) {
                        dirty++;
                    }
                }
                const lines = [
                    `Dataset: ${syncIndex.datasetName ?? cfg.datasetName}`,
                    `Dataset ID: ${datasetId ?? syncIndex.datasetId ?? "(not set)"}`,
                    `Indexed files: ${entryCount} (${entriesWithDataId} with data ID)`,
                    `Workspace files: ${files.length}`,
                    `New (unindexed): ${newCount}`,
                    `Changed (dirty): ${dirty}`,
                    `Sync index: ${SYNC_INDEX_PATH}`,
                ];
                console.log(lines.join("\n"));
            });
        }, { commands: ["cognee"] });
        // ------------------------------------------------------------------
        // Auto-sync on startup
        // ------------------------------------------------------------------
        if (cfg.autoIndex) {
            api.registerService({
                id: "cognee-auto-sync",
                async start(ctx) {
                    // Store workspace dir for use in hooks
                    resolvedWorkspaceDir = ctx.workspaceDir || process.cwd();
                    try {
                        const result = await runSync(resolvedWorkspaceDir, ctx.logger);
                        ctx.logger.info?.(`memory-cognee: auto-sync complete: ${result.added} added, ${result.updated} updated, ${result.skipped} unchanged`);
                    }
                    catch (error) {
                        ctx.logger.warn?.(`memory-cognee: auto-sync failed: ${String(error)}`);
                    }
                },
            });
        }
        // ------------------------------------------------------------------
        // Auto-recall: inject memories before each agent run
        // ------------------------------------------------------------------
        if (cfg.autoRecall) {
            api.on("before_agent_start", async (event, ctx) => {
                // Wait for state to load (fixes race condition on first agent run)
                await stateReady;

                // Skip recall for internal/automated runs — they don't need
                // memory context and waste Cognee API tokens + latency.
                const sk = ctx.sessionKey ?? "";
                if (
                    sk.includes("heartbeat") ||
                    sk.includes("cron") ||
                    sk.includes("exec-event") ||
                    sk.includes("discord:channel:1475851746550087775")
                ) {
                    api.logger.debug?.(`memory-cognee: skipping recall (internal/voice: ${sk})`);
                    return;
                }

                if (!event.prompt || event.prompt.length < 5) {
                    api.logger.debug?.("memory-cognee: skipping recall (prompt too short)");
                    return;
                }
                if (!datasetId) {
                    api.logger.debug?.("memory-cognee: skipping recall (no datasetId)");
                    return;
                }
                try {
                    const results = await client.search({
                        queryText: event.prompt,
                        searchType: cfg.searchType,
                        datasetIds: [datasetId],
                        maxTokens: cfg.maxTokens,
                    });
                    const filtered = results
                        .filter((result) => result.score >= cfg.minScore)
                        .slice(0, cfg.maxResults);
                    if (filtered.length === 0) {
                        api.logger.debug?.("memory-cognee: search returned no results above minScore");
                        return;
                    }
                    const payload = JSON.stringify(filtered.map((result) => ({
                        id: result.id,
                        score: result.score,
                        text: result.text,
                        metadata: result.metadata,
                    })), null, 2);
                    api.logger.info?.(`memory-cognee: injecting ${filtered.length} memories for session ${ctx.sessionKey ?? "unknown"}`);
                    return {
                        prependContext: `<cognee_memories>\nRelevant memories:\n${payload}\n</cognee_memories>`,
                    };
                }
                catch (error) {
                    api.logger.warn?.(`memory-cognee: recall failed: ${String(error)}`);
                }
            });
        }
        // ------------------------------------------------------------------
        // Sleep cycle: before_reset hook
        // ------------------------------------------------------------------
        // Re-entrancy guard: the sleep cycle itself triggers a reset,
        // which would fire before_reset again → infinite loop.
        let sleepCycleRunning = false;
        async function runSleepCycle(sessionFile, workspaceDir, messages, reason) {
            if (sleepCycleRunning) return;
            sleepCycleRunning = true;
            try {
                api.logger.info?.("memory-cognee: sleep cycle starting — Pass 1 cleansing");
                // Pass 1: deterministic cleansing for session transcripts and Fireflies
                // The agentic consolidation turn (Pass 2) runs in commands-core.ts
                // AFTER this hook completes, and expects frontmatted files.

                // Session transcript Pass 1
                try {
                    const { cleanseTranscript } = await import("./transcript-cleaner.js");
                    const result = await cleanseTranscript(sessionFile);
                    if (result.outputPath) {
                        api.logger.info?.(
                            `memory-cognee: transcript cleansed → ${result.outputPath} ` +
                            `(${result.stats.entryCount} entries, ${result.stats.orphanCount} orphans)`
                        );
                    }
                } catch (cleanErr) {
                    api.logger.warn?.(`memory-cognee: transcript cleansing failed: ${String(cleanErr)}`);
                }

                // Fireflies meeting transcripts Pass 1 (YAML frontmatter)
                try {
                    await cleanseFirefliesTranscripts(api.logger);
                } catch (ffErr) {
                    api.logger.warn?.(`memory-cognee: Fireflies cleansing failed: ${String(ffErr)}`);
                }

                api.logger.info?.("memory-cognee: sleep cycle Pass 1 complete");
            } catch (err) {
                api.logger.warn?.(`memory-cognee: sleep cycle failed: ${String(err)}`);
            } finally {
                sleepCycleRunning = false;
            }
        }
        api.on("before_reset", async (event, ctx) => {
            if (sleepCycleRunning || !event.sessionFile) return;
            api.logger.info?.(`memory-cognee: before_reset hook fired, running sleep cycle`);
            await runSleepCycle(event.sessionFile, ctx.workspaceDir, event.messages, event.reason);
        });
        // ------------------------------------------------------------------
        // Post-agent sync: detect file changes and sync to Cognee
        // ------------------------------------------------------------------
        if (cfg.autoIndex) {
            api.on("agent_end", async (event, ctx) => {
                // Only sync if the agent succeeded
                if (!event.success)
                    return;
                await stateReady;
                // Need workspace dir to find memory files
                const workspaceDir = resolvedWorkspaceDir || process.cwd();
                try {
                    // Collect current files and find changed ones
                    const files = await collectMemoryFiles(workspaceDir);
                    const changedFiles = files.filter((f) => {
                        const existing = syncIndex.entries[f.path];
                        return !existing || existing.hash !== f.hash;
                    });
                    if (changedFiles.length === 0)
                        return;
                    api.logger.info?.(`memory-cognee: detected ${changedFiles.length} changed file(s), syncing...`);
                    const result = await syncFiles(client, changedFiles, syncIndex, cfg, api.logger);
                    if (result.datasetId) {
                        datasetId = result.datasetId;
                    }
                    api.logger.info?.(`memory-cognee: post-agent sync: ${result.added} added, ${result.updated} updated`);
                }
                catch (error) {
                    api.logger.warn?.(`memory-cognee: post-agent sync failed: ${String(error)}`);
                }
            });
        }
        // ------------------------------------------------------------------
        // CLI: openclaw cognee consolidate
        // ------------------------------------------------------------------
        api.registerCli(async (ctx) => {
            const consolidate = ctx.program
                .command("consolidate")
                .description("Run memory consolidation on all unprocessed session transcripts.");
            consolidate.action(async () => {
                const cleanseIndexPath = join(homedir(), ".openclaw", "memory", "cognee", "cleanse-index.json");
                let cleanseIndex = { entries: {} };
                try {
                    const raw = await fs.readFile(cleanseIndexPath, "utf-8");
                    cleanseIndex = JSON.parse(raw);
                } catch { /* first run */ }
                // Find all session files across all agents
                const agentsDir = join(homedir(), ".openclaw", "agents");
                let sessionFiles = [];
                try {
                    const agentIds = await fs.readdir(agentsDir);
                    for (const agentId of agentIds) {
                        const sessionsDir = join(agentsDir, agentId, "sessions");
                        try {
                            const files = await fs.readdir(sessionsDir);
                            const jsonlFiles = files
                                .filter((f) => f.endsWith(".jsonl"))
                                .map((f) => join(sessionsDir, f));
                            sessionFiles.push(...jsonlFiles);
                        } catch { /* agent may not have sessions */ }
                    }
                } catch {
                    ctx.logger.warn?.("No agents directory found");
                    return;
                }
                ctx.logger.info?.(`Found ${sessionFiles.length} session file(s)`);
                let processed = 0;
                for (const sessionFile of sessionFiles) {
                    const filename = sessionFile.split(/[/\\]/).pop();
                    try {
                        const stat = await fs.stat(sessionFile);
                        const existing = cleanseIndex.entries[filename];
                        // Corruption check: validate fileSize + mtime
                        if (existing &&
                            existing.fileSize === stat.size &&
                            existing.mtime === stat.mtimeMs) {
                            continue; // Already processed and unchanged
                        }
                        const { cleanseTranscript } = await import("./transcript-cleaner.js");
                        const result = await cleanseTranscript(sessionFile);
                        if (result.outputPath) {
                            // Update index
                            cleanseIndex.entries[filename] = {
                                sessionId: filename.replace(/\.jsonl$/, ""),
                                fileSize: stat.size,
                                mtime: stat.mtimeMs,
                                cleansedAt: Date.now(),
                                outputPath: result.outputPath,
                            };
                            processed++;
                            ctx.logger.info?.(`Cleansed: ${filename} → ${result.outputPath}`);
                        }
                    } catch (err) {
                        ctx.logger.warn?.(`Failed to process ${filename}: ${String(err)}`);
                    }
                }
                // Save updated index
                try {
                    await fs.mkdir(dirname(cleanseIndexPath), { recursive: true });
                    await fs.writeFile(cleanseIndexPath, JSON.stringify(cleanseIndex, null, 2), "utf-8");
                } catch (err) {
                    ctx.logger.warn?.(`Failed to save cleanse index: ${String(err)}`);
                }
                ctx.logger.info?.(`Consolidation complete: ${processed} session(s) processed`);
                // Also process Fireflies meeting transcripts
                await cleanseFirefliesTranscripts(ctx.logger);
            });
        }, { commands: ["consolidate"] });
        // ------------------------------------------------------------------
        // Fireflies meeting transcript cleaner
        // ------------------------------------------------------------------
        async function cleanseFirefliesTranscripts(logger) {
            const rawDir = join(homedir(), ".openclaw", "workspace", "bpc_transcripts");
            const outputDir = join(homedir(), ".openclaw", "workspace", ".staging", "meetings");
            let files = [];
            try {
                files = (await fs.readdir(rawDir)).filter((f) => f.endsWith(".txt"));
            } catch {
                logger?.debug?.("No Fireflies transcripts directory found");
                return;
            }
            if (files.length === 0) return;
            logger?.info?.(`Found ${files.length} Fireflies transcript(s) to process`);
            await fs.mkdir(outputDir, { recursive: true });
            let processed = 0;
            for (const file of files) {
                const inputPath = join(rawDir, file);
                const outputFile = file.replace(/\.txt$/, ".md");
                const outputPath = join(outputDir, outputFile);
                // Skip if already cleaned
                try {
                    await fs.access(outputPath);
                    continue; // Already exists
                } catch { /* doesn't exist yet, proceed */ }
                try {
                    const content = await fs.readFile(inputPath, "utf-8");
                    // Extract metadata from filename pattern:
                    // 2026-02-27T15-30-00-000Z_heavenly_holidays_purchase_order_fun.txt
                    const isoMatch = file.match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-\d{2}-\d{3}Z_(.+)\.txt$/);
                    const date = isoMatch ? isoMatch[1] : file.match(/^(\d{4}-\d{2}-\d{2})/)?.[1] || new Date().toISOString().split("T")[0];
                    const time = isoMatch ? `${isoMatch[2]}:${isoMatch[3]}` : undefined;
                    const titleRaw = isoMatch
                        ? isoMatch[4]
                        : file.replace(/^\d{4}-\d{2}-\d{2}T[^_]*_?/, "").replace(/\.txt$/, "");
                    const title = titleRaw.replace(/_/g, " ").trim() || "Meeting";
                    // Extract participants from speaker labels: [Speaker Name]: text
                    const speakerPattern = /^\[([^\]]+)\]:\s/gm;
                    const speakers = new Set();
                    let match;
                    while ((match = speakerPattern.exec(content)) !== null) {
                        const speaker = match[1].trim();
                        if (speaker.length > 1 && speaker.length < 50) {
                            speakers.add(speaker);
                        }
                    }
                    // Build frontmatter
                    const frontmatter = [
                        "---",
                        "type: meeting",
                        "source: fireflies",
                        `date: ${date}`,
                        time ? `time: "${time} UTC"` : null,
                        `participants: [${[...speakers].join(", ")}]`,
                        `title: "${title}"`,
                        "---",
                        "",
                    ].filter(Boolean).join("\n");
                    await fs.writeFile(outputPath, frontmatter + content, "utf-8");
                    processed++;
                    logger?.info?.(`Fireflies: ${file} → ${outputFile}`);
                } catch (err) {
                    logger?.warn?.(`Failed to process Fireflies transcript ${file}: ${String(err)}`);
                }
            }
            if (processed > 0) {
                logger?.info?.(`Fireflies: ${processed} transcript(s) processed`);
            }
        }
    },
};
export default memoryCogneePlugin;
//# sourceMappingURL=index.js.map
