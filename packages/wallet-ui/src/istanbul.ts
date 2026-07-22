export type NodeCapabilitySource = "reported" | "legacy_type2";

export type NodeFeatureFlags = {
  action_guard: boolean;
  tx_blob: boolean;
  ast: boolean;
  tex: boolean;
  native_assets: boolean;
  hip20_primitives?: boolean;
  hip20: boolean;
  hvm: boolean;
  p2sh: boolean;
  account_abstraction: boolean;
  intent: boolean;
  contract_state_leasing: boolean;
  ir_decompilation: boolean;
  req_sign_list: boolean;
  type4_mainnet: boolean;
  exact_unsigned_simulation: boolean;
};

export type NodeCapabilities = {
  ret: number;
  api_version: number;
  node: {
    name: string;
    version: string;
    build_time: string;
  };
  chain: {
    id: number;
    height: number;
    next_height: number;
    mainnet: boolean;
  };
  istanbul: {
    activation_height: number;
    evaluation_height: number;
    active: boolean;
  };
  transactions: {
    registered: number[];
    enabled: number[];
  };
  actions: {
    registered: number[];
    enabled: number[];
  };
  features: NodeFeatureFlags;
  limits: {
    max_tx_size: number;
    max_tx_actions: number;
    max_type3_signers: number;
    gas_max_byte: number;
    gas_max: number;
    ast_depth: number;
  };
  source: NodeCapabilitySource;
};

export type AddressKind = "private_key" | "contract" | "p2sh" | "pqc" | "hybrid";

export type ParsedAddress = {
  address: string;
  version: number;
  kind: AddressKind;
  network_mode: string;
  network_allowed: boolean;
  passive_receive: boolean;
  fast_pay_eligible: boolean;
  warning?: string | null;
};

export type CanonicalAction = {
  kind: number;
  description: string;
  canonical_json: unknown;
};

export type CanonicalTransaction = {
  tx_type: number;
  gas_max: number | null;
  main_address: string;
  fee: string;
  body_sha256: string;
  required_signers: string[];
  signer_policy: "at_least" | "exact";
  actions: CanonicalAction[];
};

export const ISTANBUL_FEATURES = [
  "action_guard",
  "tx_blob",
  "ast",
  "tex",
  "native_assets",
  "hip20_primitives",
  "hip20",
  "hvm",
  "p2sh",
  "account_abstraction",
  "intent",
  "contract_state_leasing",
  "ir_decompilation",
  "req_sign_list",
  "exact_unsigned_simulation",
  "type4_mainnet",
] as const satisfies readonly (keyof NodeFeatureFlags)[];

export type IstanbulFeature = (typeof ISTANBUL_FEATURES)[number];

const REQUIRED_ISTANBUL_FEATURES = [
  "action_guard",
  "tx_blob",
  "ast",
  "tex",
  "native_assets",
  "hip20_primitives",
  "hvm",
  "p2sh",
  "account_abstraction",
  "intent",
  "contract_state_leasing",
  "req_sign_list",
] as const satisfies readonly IstanbulFeature[];

export type IstanbulReadiness = {
  status: "ready" | "partial" | "inactive" | "legacy";
  missing: IstanbulFeature[];
};

export function assessIstanbulNode(capabilities: NodeCapabilities): IstanbulReadiness {
  if (capabilities.source === "legacy_type2") {
    return { status: "legacy", missing: [...REQUIRED_ISTANBUL_FEATURES] };
  }

  const missing = REQUIRED_ISTANBUL_FEATURES.filter(
    (feature) => capabilities.features[feature] !== true,
  );
  if (capabilities.ret !== 0 || !capabilities.istanbul.active) {
    return { status: "inactive", missing };
  }
  if (!capabilities.transactions.enabled.includes(3) || missing.length > 0) {
    return { status: "partial", missing };
  }
  return { status: "ready", missing: [] };
}

export function istanbulFeatureMessageKey(feature: IstanbulFeature): string {
  return `istanbul.feature.${feature}`;
}

export function addressKindMessageKey(kind: AddressKind): string {
  return `istanbul.address.kind.${kind}`;
}

export function addressWarningMessageKey(parsed: ParsedAddress): string | null {
  if (!parsed.warning) return null;
  if (!parsed.network_allowed && (parsed.kind === "pqc" || parsed.kind === "hybrid")) {
    return "istanbul.address.warning.quantumMainnet";
  }
  if (parsed.kind === "contract") return "istanbul.address.warning.contract";
  if (parsed.kind === "p2sh") return "istanbul.address.warning.p2sh";
  return "istanbul.address.warning.generic";
}

export function reconcileAddressDraft(
  draft: string,
  previousCurrentAddress: string | null | undefined,
  nextCurrentAddress: string | null | undefined,
): string {
  const previous = previousCurrentAddress?.trim() ?? "";
  const next = nextCurrentAddress?.trim() ?? "";
  return previous === next ? draft : next;
}

export const MAX_TRANSACTION_HEX_CHARS = 512 * 1024;

export function normalizeTransactionHex(input: string): string {
  const compact = input.replace(/\s+/g, "");
  return compact.startsWith("0x") || compact.startsWith("0X") ? compact.slice(2) : compact;
}

export function isInspectableTransactionHex(input: string): boolean {
  const normalized = normalizeTransactionHex(input);
  return normalized.length >= 2
    && normalized.length <= MAX_TRANSACTION_HEX_CHARS
    && normalized.length % 2 === 0
    && /^[0-9a-fA-F]+$/.test(normalized);
}
