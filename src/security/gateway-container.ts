import { spawn, type ChildProcess } from "node:child_process";
import process from "node:process";
import { execDocker, dockerContainerState } from "../agents/sandbox/docker.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const logger = createSubsystemLogger("security/gateway-container");

const GATEWAY_IMAGE = "openclaw-gateway:latest";
const GATEWAY_CONTAINER_NAME = "openclaw-gateway-secure";

export type ServiceRelay = {
  /** Human-readable name for logging (e.g. "speaches"). */
  name: string;
  /** Port the relay listens on inside the internal network. */
  containerPort: number;
  /** Port on the host to forward to (via host.docker.internal on Windows, socket on Linux). */
  hostPort: number;
  /** Env var name to set in the gateway container (value = relay hostname:port). */
  envVar?: string;
};

export type GatewayContainerOptions = {
  /** Gateway WebSocket port (host and container) */
  gatewayPort: number;
  /** Port the relay listens on inside the internal network */
  proxyPort: number;
  /** Port the host proxy is listening on (defaults to proxyPort if not set) */
  hostProxyPort?: number;
  /** Unix socket path to the host proxy (Linux/macOS). Mutually exclusive with TCP mode. */
  proxySocketPath?: string;
  env?: Record<string, string | undefined>;
  /** Bind mounts in format ["host:container:ro"] */
  binds?: string[];
  /** Additional service relays (e.g. Speaches STT). */
  serviceRelays?: ServiceRelay[];
};

const SECURE_NETWORK_NAME = "openclaw-secure-net";
export const RELAY_CONTAINER_NAME = "openclaw-relay";
const SOCAT_IMAGE = "alpine/socat";
const RELAY_SOCKET_MOUNT = "/tmp/proxy.sock";

/**
 * Create the internal Docker network (blocks all outbound internet).
 * Idempotent — silently succeeds if the network already exists.
 */
async function ensureSecureNetwork(): Promise<void> {
  const result = await execDocker(["network", "inspect", SECURE_NETWORK_NAME], {
    allowFailure: true,
  });
  if (result.code === 0) {
    logger.debug(`Network ${SECURE_NETWORK_NAME} already exists`);
    return;
  }
  logger.info(`Creating internal Docker network: ${SECURE_NETWORK_NAME}`);
  await execDocker(["network", "create", "--internal", SECURE_NETWORK_NAME]);
}

/**
 * Remove the internal Docker network.
 */
async function removeSecureNetwork(): Promise<void> {
  try {
    await execDocker(["network", "rm", SECURE_NETWORK_NAME], { allowFailure: true });
    logger.info(`Removed network: ${SECURE_NETWORK_NAME}`);
  } catch {
    // Network may not exist or may still have endpoints
  }
}

/**
 * Start a socat relay container that bridges the internal network to the host proxy.
 *
 * Socket mode (Linux/macOS): mount the host proxy's Unix socket into the relay.
 *   socat TCP-LISTEN → UNIX-CONNECT:/tmp/proxy.sock
 *   No TCP exposure on any network interface.
 *
 * TCP mode (Windows): relay connects to host.docker.internal (Docker Desktop loopback).
 *   socat TCP-LISTEN → TCP:host.docker.internal:port
 *   Proxy is on 127.0.0.1, reachable only via Docker Desktop's host gateway.
 */
async function startRelayContainer(
  proxyPort: number,
  hostProxyPort: number,
  proxySocketPath?: string,
): Promise<void> {
  // Remove any existing relay
  try {
    await execDocker(["rm", "-f", RELAY_CONTAINER_NAME], { allowFailure: true });
  } catch {
    // ignore
  }

  // Always start on the internal network — never on bridge.
  // On Docker Desktop (Windows), host.docker.internal resolves from any network,
  // so there's no need to start on bridge and then hot-swap networks.
  const network = SECURE_NETWORK_NAME;

  const args = [
    "run",
    "-d",
    "--name",
    RELAY_CONTAINER_NAME,
    "--network",
    network,
    "--restart",
    "unless-stopped",
  ];

  if (proxySocketPath) {
    // Socket mode: mount host socket into relay container
    args.push("-v", `${proxySocketPath}:${RELAY_SOCKET_MOUNT}:ro`);
    args.push(
      SOCAT_IMAGE,
      `TCP-LISTEN:${proxyPort},fork,reuseaddr`,
      `UNIX-CONNECT:${RELAY_SOCKET_MOUNT}`,
    );
  } else {
    // TCP mode (Windows): reach host via Docker Desktop's host.docker.internal
    args.push(
      "--add-host",
      "host.docker.internal:host-gateway",
      SOCAT_IMAGE,
      `TCP-LISTEN:${proxyPort},fork,reuseaddr`,
      `TCP:host.docker.internal:${hostProxyPort}`,
    );
  }

  await execDocker(args);

  const mode = proxySocketPath
    ? `socket:${proxySocketPath}`
    : `tcp:host.docker.internal:${hostProxyPort}`;
  logger.info(`Relay container started: ${RELAY_CONTAINER_NAME} (${mode} → port ${proxyPort})`);
}

/**
 * Stop and remove the relay container.
 */
async function stopRelayContainer(): Promise<void> {
  try {
    await execDocker(["rm", "-f", RELAY_CONTAINER_NAME], { allowFailure: true });
    logger.info(`Removed relay container: ${RELAY_CONTAINER_NAME}`);
  } catch {
    // ignore
  }
}

/**
 * Start a service relay container that bridges a host service (e.g. Speaches)
 * into the internal network so the gateway container can reach it.
 */
async function startServiceRelayContainer(relay: ServiceRelay): Promise<string> {
  const containerName = `openclaw-relay-${relay.name}`;
  // Remove any existing relay for this service
  try {
    await execDocker(["rm", "-f", containerName], { allowFailure: true });
  } catch {
    // ignore
  }

  const args = [
    "run",
    "-d",
    "--name",
    containerName,
    "--network",
    SECURE_NETWORK_NAME,
    "--restart",
    "unless-stopped",
    "--add-host",
    "host.docker.internal:host-gateway",
    SOCAT_IMAGE,
    `TCP-LISTEN:${relay.containerPort},fork,reuseaddr`,
    `TCP:host.docker.internal:${relay.hostPort}`,
  ];

  await execDocker(args);
  logger.info(
    `Service relay started: ${containerName} (host.docker.internal:${relay.hostPort} → port ${relay.containerPort})`,
  );
  return containerName;
}

/** Track service relay container names for cleanup. */
const activeServiceRelays: string[] = [];

/**
 * Stop all service relay containers.
 */
async function stopServiceRelayContainers(): Promise<void> {
  for (const name of activeServiceRelays) {
    try {
      await execDocker(["rm", "-f", name], { allowFailure: true });
      logger.info(`Removed service relay: ${name}`);
    } catch {
      // ignore
    }
  }
  activeServiceRelays.length = 0;
}

/**
 * Full cleanup: gateway container, relay container, and internal network.
 */
export async function stopGatewayContainer(): Promise<void> {
  stopSocatForwarder();
  const state = await dockerContainerState(GATEWAY_CONTAINER_NAME);
  if (state.exists) {
    logger.info(`Stopping existing gateway container: ${GATEWAY_CONTAINER_NAME}`);
    await execDocker(["rm", "-f", GATEWAY_CONTAINER_NAME]);
  }
  await stopServiceRelayContainers();
  await stopRelayContainer();
  await removeSecureNetwork();
}

/** Host-side socat process for forwarding the gateway port to the container's internal IP. */
let socatProcess: ChildProcess | null = null;

/**
 * Get the container's IP address on the internal network.
 */
async function getContainerIp(containerName: string, networkName: string): Promise<string> {
  const result = await execDocker([
    "inspect",
    "--format",
    `{{(index .NetworkSettings.Networks "${networkName}").IPAddress}}`,
    containerName,
  ]);
  const ip = result.stdout.trim();
  if (!ip) {
    throw new Error(`Could not get IP of ${containerName} on network ${networkName}`);
  }
  return ip;
}

/**
 * Start a host-side socat process to forward hostPort → containerIp:containerPort.
 * This allows the gateway port to be accessible on the host without putting the
 * container on the bridge network (which would give it outbound internet access).
 */
function startSocatForwarder(
  hostPort: number,
  containerIp: string,
  containerPort: number,
): ChildProcess {
  const proc = spawn(
    "socat",
    [`TCP-LISTEN:${hostPort},bind=127.0.0.1,fork,reuseaddr`, `TCP:${containerIp}:${containerPort}`],
    { stdio: "ignore", detached: false },
  );
  proc.on("error", (err) => {
    logger.error(`socat forwarder error: ${String(err)}`);
  });
  proc.on("exit", (code) => {
    if (code !== null && code !== 0) {
      logger.warn(`socat forwarder exited with code ${code}`);
    }
  });
  logger.info(`socat forwarder started: 127.0.0.1:${hostPort} → ${containerIp}:${containerPort}`);
  return proc;
}

/**
 * Stop the host-side socat forwarder if running.
 */
function stopSocatForwarder(): void {
  if (socatProcess) {
    socatProcess.kill();
    socatProcess = null;
    logger.info("socat forwarder stopped");
  }
}

export async function startGatewayContainer(opts: GatewayContainerOptions): Promise<string> {
  await stopGatewayContainer();

  // Set up network isolation: internal network + relay
  await ensureSecureNetwork();
  await startRelayContainer(
    opts.proxyPort,
    opts.hostProxyPort ?? opts.proxyPort,
    opts.proxySocketPath,
  );

  const filteredEnv = filterSecretEnv(opts.env || process.env);

  // Resolve the relay container's IP on the internal network for PROXY_URL
  // The gateway container uses the relay's hostname (Docker DNS on user-defined networks)
  const proxyUrl = `http://${RELAY_CONTAINER_NAME}:${opts.proxyPort}`;

  const args = [
    "run",
    "-d",
    "--name",
    GATEWAY_CONTAINER_NAME,
    // Internal-only network: blocks ALL outbound internet access
    "--network",
    SECURE_NETWORK_NAME,
    // Tell container to bind to the configured port
    "-e",
    `PORT=${opts.gatewayPort}`,
    // Set secure mode flag so gateway knows to use placeholders and fetch wrapper
    "-e",
    "OPENCLAW_SECURE_MODE=1",
    // Tell the container where the proxy is (via relay on the internal network)
    "-e",
    `PROXY_URL=${proxyUrl}`,
    // Explicitly set container paths to prevent host paths from being used
    "-e",
    "OPENCLAW_STATE_DIR=/home/node/.openclaw",
    "-e",
    "HOME=/home/node",
    "-e",
    "USER=node",
    "-e",
    "LOGNAME=node",
    "-e",
    "PWD=/app",
    "-e",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "-e",
    "XDG_CACHE_HOME=/home/node/.cache",
    "-e",
    "XDG_CONFIG_HOME=/home/node/.config",
  ];

  // Start service relays (e.g. Speaches STT) BEFORE the gateway so env vars
  // can be injected at container launch time.
  for (const relay of opts.serviceRelays ?? []) {
    const relayName = await startServiceRelayContainer(relay);
    activeServiceRelays.push(relayName);
    if (relay.envVar) {
      const relayUrl = `http://${relayName}:${relay.containerPort}`;
      args.push("-e", `${relay.envVar}=${relayUrl}`);
      logger.info(`Service relay ${relay.name}: ${relay.envVar}=${relayUrl}`);
    }
  }

  // Add bind mounts for tools/skills
  for (const bind of opts.binds || []) {
    // Validate bind mount format
    if (/^[^:]+:[^:]+(:(ro|rw))?$/.test(bind)) {
      args.push("-v", bind);
      logger.info(`Adding bind mount: ${bind}`);
    } else {
      logger.warn(`Invalid bind mount format (expected host:container[:ro|rw]): ${bind}`);
    }
  }

  // Keys that are explicitly set above - don't override with filteredEnv
  const explicitlySetKeys = new Set([
    "PORT",
    "OPENCLAW_SECURE_MODE",
    "PROXY_URL",
    "OPENCLAW_STATE_DIR",
    "HOME",
    "USER",
    "LOGNAME",
    "PWD",
    "PATH",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
  ]);

  // Add filtered environment variables (excluding explicitly set keys)
  for (const [key, value] of Object.entries(filteredEnv)) {
    if (explicitlySetKeys.has(key.toUpperCase())) {
      logger.debug(`Skipping explicitly set env var: ${key}`);
      continue;
    }
    if (/[\n\r]/.test(value ?? "")) {
      logger.warn(`Skipping env var with newline: ${key}`);
      continue;
    }
    args.push("-e", `${key}=${value}`);
  }

  args.push(GATEWAY_IMAGE);

  // Bind to lan (all interfaces) inside container — safe since the container holds no
  // secrets (only placeholders). The host socat forwarder restricts access to 127.0.0.1
  // on the host side.
  args.push("node", "dist/index.js", "gateway", "--allow-unconfigured", "--bind", "lan");

  logger.info(
    `Starting gateway container: ${GATEWAY_CONTAINER_NAME} (network: ${SECURE_NETWORK_NAME})`,
  );
  await execDocker(args);

  // Also connect the container to the default bridge network for outbound internet access.
  // This is required for Discord voice connections (WebSocket signaling + UDP audio to
  // dynamic *.discord.media servers) which cannot be proxied through the relay.
  // The container holds no secrets (only placeholders injected by the secrets proxy),
  // so outbound access does not weaken the security model.
  await execDocker(["network", "connect", "bridge", GATEWAY_CONTAINER_NAME]);
  logger.info(`Connected ${GATEWAY_CONTAINER_NAME} to bridge network for outbound access`);

  // Get the container's IP on the internal network and start a host-side socat forwarder.
  // This makes the gateway port accessible on the host (127.0.0.1:gatewayPort) without
  // requiring the container to expose ports on the bridge network.
  const containerIp = await getContainerIp(GATEWAY_CONTAINER_NAME, SECURE_NETWORK_NAME);
  socatProcess = startSocatForwarder(opts.gatewayPort, containerIp, opts.gatewayPort);

  return GATEWAY_CONTAINER_NAME;
}

/**
 * Checks if the gateway container is running and healthy.
 */
export async function isGatewayContainerRunning(): Promise<boolean> {
  const state = await dockerContainerState(GATEWAY_CONTAINER_NAME);
  return state.exists && state.running;
}

/**
 * Gets the gateway container logs.
 */
export async function getGatewayContainerLogs(lines: number = 50): Promise<string> {
  try {
    const result = await execDocker(["logs", "--tail", String(lines), GATEWAY_CONTAINER_NAME]);
    // execDocker returns {stdout, stderr, code} - combine for logs
    return result.stdout + (result.stderr ? "\n" + result.stderr : "");
  } catch (err) {
    return `Failed to get logs: ${String(err)}`;
  }
}

/**
 * P1 Fix: Comprehensive list of secret env var patterns.
 * Includes suffixes, prefixes, and exact matches for common secrets.
 */
const SECRET_SUFFIXES = [
  "_API_KEY",
  "_TOKEN",
  "_SECRET",
  "_PASSWORD",
  "_CREDENTIAL",
  "_CREDENTIALS",
  "_KEY",
  "_PRIVATE_KEY",
];

const SECRET_PREFIXES: string[] = [
  // Removed AWS_, AZURE_, GOOGLE_, GCP_ - too broad, blocks non-secret config
  // like AWS_REGION, GOOGLE_CLOUD_PROJECT. Use exact matches instead.
];

const SECRET_EXACT_MATCHES = new Set([
  // AWS specific
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  // Database
  "DATABASE_URL",
  "DATABASE_PASSWORD",
  "DB_PASSWORD",
  "REDIS_URL",
  "REDIS_PASSWORD",
  "MONGO_URL",
  "MONGODB_URI",
  "POSTGRES_PASSWORD",
  "MYSQL_PASSWORD",
  // Auth
  "PASSWORD",
  "COOKIE",
  "SESSION_SECRET",
  "JWT_SECRET",
  "AUTH_SECRET",
  // Generic
  "PRIVATE_KEY",
  "SECRET",
  "CREDENTIALS",
  // Path-related (prevent host paths in container)
  "HOME",
  "OPENCLAW_STATE_DIR",
  "OPENCLAW_CONFIG_PATH",
  "CLAWDBOT_STATE_DIR",
  "CLAWDBOT_CONFIG_PATH",
  // User/session related (prevent host user leaking)
  "USER",
  "LOGNAME",
  "USERNAME",
  "PWD",
  "OLDPWD",
  "PATH",
  // XDG dirs (contain host paths)
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_STATE_HOME",
  "XDG_RUNTIME_DIR",
  // NVM (contains host paths)
  "NVM_DIR",
  "NVM_BIN",
  "NVM_INC",
  // Shell internals (contain host paths)
  "_", // Last executed command path
]);

/**
 * Env vars that should be passed to container despite matching secret patterns.
 * These are OpenClaw-specific credentials needed for gateway operation.
 */
const ALLOWED_SECRET_ENV_VARS = new Set([
  "OPENCLAW_GATEWAY_TOKEN", // Gateway auth token
  "OPENCLAW_GATEWAY_PASSWORD", // Gateway auth password
  "CLAWDBOT_GATEWAY_TOKEN", // Legacy alias
  "CLAWDBOT_GATEWAY_PASSWORD", // Legacy alias
  "PROXY_AUTH_TOKEN", // Proxy client auth (generated per-session)
  "OPENCLAW_EMBEDDED_NODE_HOST_TOKEN", // Per-session token for embedded node host auth bypass
]);

/**
 * Filters environment variables to exclude secrets.
 * P1 Fix: Now covers AWS credentials and other common secret patterns.
 */
function filterSecretEnv(env: Record<string, string | undefined>): Record<string, string> {
  const filtered: Record<string, string> = {};

  for (const [key, value] of Object.entries(env)) {
    if (!value) {
      continue;
    }

    const upperKey = key.toUpperCase();

    // Allow OpenClaw-specific env vars needed for gateway operation
    if (ALLOWED_SECRET_ENV_VARS.has(upperKey)) {
      filtered[key] = value;
      continue;
    }

    // Check exact matches first
    if (SECRET_EXACT_MATCHES.has(upperKey)) {
      logger.debug(`Filtered secret env var (exact match): ${key}`);
      continue;
    }

    // Check suffixes
    const hasSuffix = SECRET_SUFFIXES.some((suffix) => upperKey.endsWith(suffix));
    if (hasSuffix) {
      logger.debug(`Filtered secret env var (suffix): ${key}`);
      continue;
    }

    // Check prefixes (these cloud provider env vars often contain credentials)
    const hasPrefix = SECRET_PREFIXES.some((prefix) => upperKey.startsWith(prefix));
    if (hasPrefix) {
      logger.debug(`Filtered secret env var (prefix): ${key}`);
      continue;
    }

    filtered[key] = value;
  }

  return filtered;
}
