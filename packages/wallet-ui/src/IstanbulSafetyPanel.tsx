import { useCallback, useEffect, useRef, useState } from "react";

import "./istanbul.css";
import {
  ISTANBUL_FEATURES,
  MAX_TRANSACTION_HEX_CHARS,
  addressKindMessageKey,
  addressWarningMessageKey,
  assessIstanbulNode,
  isInspectableTransactionHex,
  istanbulFeatureMessageKey,
  normalizeTransactionHex,
  reconcileAddressDraft,
  type CanonicalTransaction,
  type NodeCapabilities,
  type ParsedAddress,
} from "./istanbul";
import { useLocale } from "./i18n";

type Probe<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ok"; value: T }
  | { status: "failed"; message: string };

export type IstanbulSafetyCommands = {
  nodeCapabilities: () => Promise<NodeCapabilities>;
  inspectAddress: (
    address: string,
    networkMode?: "mainnet" | "testnet",
  ) => Promise<ParsedAddress>;
  inspectTransaction: (
    bodyHex: string,
    expectedChainId?: number,
  ) => Promise<CanonicalTransaction>;
};

type Props = {
  commands: IstanbulSafetyCommands;
  networkMode: "mainnet" | "testnet";
  currentAddress?: string | null;
  containerClassName?: string;
  formatError?: (cause: unknown) => string;
};

function defaultFormatError(cause: unknown): string {
  if (cause instanceof Error && cause.message) return cause.message;
  if (typeof cause === "string" && cause.trim()) return cause;
  if (cause && typeof cause === "object" && "message" in cause) {
    const message = (cause as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) return message;
  }
  return "";
}

function ProbeError({ probe }: { probe: Probe<unknown> }) {
  if (probe.status !== "failed") return null;
  return <p className="istanbul-error" role="alert">{probe.message}</p>;
}

function OnOff({ enabled }: { enabled: boolean }) {
  const { t } = useLocale();
  return (
    <span className={`istanbul-flag ${enabled ? "is-on" : "is-off"}`}>
      {t(enabled ? "status.on" : "status.off")}
    </span>
  );
}

export function IstanbulSafetyPanel({
  commands,
  networkMode,
  currentAddress,
  containerClassName = "",
  formatError = defaultFormatError,
}: Props) {
  const { locale, t } = useLocale();
  const [capabilities, setCapabilities] = useState<Probe<NodeCapabilities>>({ status: "idle" });
  const [addressInput, setAddressInput] = useState(currentAddress ?? "");
  const [addressProbe, setAddressProbe] = useState<Probe<ParsedAddress>>({ status: "idle" });
  const [bodyHex, setBodyHex] = useState("");
  const [transactionProbe, setTransactionProbe] = useState<Probe<CanonicalTransaction>>({
    status: "idle",
  });
  const capabilityGeneration = useRef(0);
  const addressGeneration = useRef(0);
  const transactionGeneration = useRef(0);
  const previousCurrentAddress = useRef(currentAddress ?? "");

  const errorMessage = useCallback(
    (cause: unknown) => formatError(cause).trim() || t("istanbul.requestFailed"),
    [formatError, t],
  );

  const refreshCapabilities = useCallback(async () => {
    const generation = ++capabilityGeneration.current;
    setCapabilities({ status: "loading" });
    try {
      const value = await commands.nodeCapabilities();
      if (generation === capabilityGeneration.current) {
        setCapabilities({ status: "ok", value });
      }
    } catch (cause) {
      if (generation === capabilityGeneration.current) {
        setCapabilities({ status: "failed", message: errorMessage(cause) });
      }
    }
  }, [commands, errorMessage]);

  useEffect(() => {
    void refreshCapabilities();
    return () => {
      capabilityGeneration.current += 1;
      addressGeneration.current += 1;
      transactionGeneration.current += 1;
    };
  }, [refreshCapabilities]);

  useEffect(() => {
    const previous = previousCurrentAddress.current;
    const next = currentAddress ?? "";
    if (previous.trim() === next.trim()) {
      previousCurrentAddress.current = next;
      return;
    }

    previousCurrentAddress.current = next;
    addressGeneration.current += 1;
    setAddressInput((draft) => reconcileAddressDraft(draft, previous, next));
    setAddressProbe({ status: "idle" });
  }, [currentAddress]);

  useEffect(() => {
    addressGeneration.current += 1;
    setAddressProbe({ status: "idle" });
  }, [networkMode]);

  const inspectAddress = async () => {
    const address = addressInput.trim();
    if (!address) return;
    const generation = ++addressGeneration.current;
    setAddressProbe({ status: "loading" });
    try {
      const value = await commands.inspectAddress(address, networkMode);
      if (generation === addressGeneration.current) {
        setAddressProbe({ status: "ok", value });
      }
    } catch (cause) {
      if (generation === addressGeneration.current) {
        setAddressProbe({ status: "failed", message: errorMessage(cause) });
      }
    }
  };

  const inspectTransaction = async () => {
    if (!isInspectableTransactionHex(bodyHex)) {
      setTransactionProbe({ status: "failed", message: t("istanbul.invalidHex") });
      return;
    }
    const generation = ++transactionGeneration.current;
    setTransactionProbe({ status: "loading" });
    const expectedChainId = capabilities.status === "ok"
      && capabilities.value.source === "reported"
      ? capabilities.value.chain.id
      : undefined;
    try {
      const value = await commands.inspectTransaction(
        normalizeTransactionHex(bodyHex),
        expectedChainId,
      );
      if (generation === transactionGeneration.current) {
        setTransactionProbe({ status: "ok", value });
      }
    } catch (cause) {
      if (generation === transactionGeneration.current) {
        setTransactionProbe({ status: "failed", message: errorMessage(cause) });
      }
    }
  };

  const readiness = capabilities.status === "ok"
    ? assessIstanbulNode(capabilities.value)
    : null;
  const readinessKey = readiness ? `istanbul.node.${readiness.status}` : "";
  const txHexValid = isInspectableTransactionHex(bodyHex);

  return (
    <section className={`istanbul-safety ${containerClassName}`.trim()}>
      <header className="istanbul-safety-header">
        <div>
          <h2>{t("istanbul.title")}</h2>
          <p>{t("istanbul.subtitle")}</p>
        </div>
        <button
          type="button"
          className="istanbul-refresh"
          disabled={capabilities.status === "loading"}
          onClick={() => void refreshCapabilities()}
        >
          {capabilities.status === "loading" ? t("istanbul.checking") : t("common.refresh")}
        </button>
      </header>

      {capabilities.status === "loading" ? (
        <p className="istanbul-muted" aria-live="polite">{t("istanbul.checking")}</p>
      ) : null}
      <ProbeError probe={capabilities} />

      {capabilities.status === "ok" && readiness ? (
        <div className="istanbul-node-report">
          <div className={`istanbul-readiness is-${readiness.status}`}>
            <strong>{t(readinessKey)}</strong>
            <span>
              {capabilities.value.node.name} {capabilities.value.node.version}
            </span>
          </div>
          <dl className="istanbul-facts">
            <div><dt>{t("istanbul.fact.chainId")}</dt><dd>{capabilities.value.chain.id}</dd></div>
            <div><dt>{t("istanbul.fact.height")}</dt><dd>{capabilities.value.chain.height.toLocaleString(locale)}</dd></div>
            <div><dt>{t("istanbul.fact.activation")}</dt><dd>{capabilities.value.istanbul.activation_height.toLocaleString(locale)}</dd></div>
            <div><dt>{t("istanbul.fact.type3")}</dt><dd><OnOff enabled={capabilities.value.transactions.enabled.includes(3)} /></dd></div>
            <div><dt>{t("istanbul.fact.source")}</dt><dd>{t(`istanbul.source.${capabilities.value.source}`)}</dd></div>
            <div><dt>{t("istanbul.fact.maxActions")}</dt><dd>{capabilities.value.limits.max_tx_actions}</dd></div>
          </dl>
          {readiness.missing.length > 0 ? (
            <p className="istanbul-notice">
              {t("istanbul.missing")}: {readiness.missing.map((feature) => t(istanbulFeatureMessageKey(feature))).join(", ")}
            </p>
          ) : null}
          <div className="istanbul-feature-grid" aria-label={t("istanbul.features")}>
            {ISTANBUL_FEATURES.map((feature) => (
              <div className="istanbul-feature" key={feature}>
                <span>{t(istanbulFeatureMessageKey(feature))}</span>
                <OnOff enabled={capabilities.value.features[feature] === true} />
              </div>
            ))}
          </div>
          {!capabilities.value.features.type4_mainnet ? (
            <p className="istanbul-notice">{t("istanbul.type4Disabled")}</p>
          ) : null}
        </div>
      ) : null}

      <div className="istanbul-inspectors">
        <form
          className="istanbul-inspector"
          onSubmit={(event) => {
            event.preventDefault();
            void inspectAddress();
          }}
        >
          <h3>{t("istanbul.addressTitle")}</h3>
          <p className="istanbul-muted">{t("istanbul.addressHelp")}</p>
          <input
            aria-label={t("istanbul.addressTitle")}
            value={addressInput}
            maxLength={80}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            onChange={(event) => {
              setAddressInput(event.target.value);
              setAddressProbe({ status: "idle" });
            }}
            placeholder={t("istanbul.addressPlaceholder")}
          />
          <button
            type="submit"
            disabled={!addressInput.trim() || addressProbe.status === "loading"}
          >
            {addressProbe.status === "loading" ? t("istanbul.inspecting") : t("istanbul.inspect")}
          </button>
          <ProbeError probe={addressProbe} />
          {addressProbe.status === "ok" ? (
            <div className="istanbul-result">
              <strong>{t(addressKindMessageKey(addressProbe.value.kind))}</strong>
              <code>{addressProbe.value.address}</code>
              <dl className="istanbul-facts">
                <div><dt>{t("istanbul.fact.version")}</dt><dd>{addressProbe.value.version}</dd></div>
                <div><dt>{t("istanbul.fact.network")}</dt><dd>{addressProbe.value.network_mode}</dd></div>
                <div><dt>{t("istanbul.fact.allowed")}</dt><dd><OnOff enabled={addressProbe.value.network_allowed} /></dd></div>
                <div><dt>{t("istanbul.fact.passiveReceive")}</dt><dd><OnOff enabled={addressProbe.value.passive_receive} /></dd></div>
                <div><dt>{t("istanbul.fact.fastPay")}</dt><dd><OnOff enabled={addressProbe.value.fast_pay_eligible} /></dd></div>
              </dl>
              {addressWarningMessageKey(addressProbe.value) ? (
                <p className="istanbul-notice">
                  {t(addressWarningMessageKey(addressProbe.value) ?? "istanbul.address.warning.generic")}
                </p>
              ) : null}
            </div>
          ) : null}
        </form>

        <form
          className="istanbul-inspector"
          onSubmit={(event) => {
            event.preventDefault();
            void inspectTransaction();
          }}
        >
          <h3>{t("istanbul.transactionTitle")}</h3>
          <p className="istanbul-muted">{t("istanbul.transactionHelp")}</p>
          <textarea
            aria-label={t("istanbul.transactionTitle")}
            value={bodyHex}
            rows={5}
            maxLength={MAX_TRANSACTION_HEX_CHARS}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            onChange={(event) => {
              setBodyHex(event.target.value);
              setTransactionProbe({ status: "idle" });
            }}
            placeholder={t("istanbul.transactionPlaceholder")}
          />
          <button
            type="submit"
            disabled={!txHexValid || transactionProbe.status === "loading"}
          >
            {transactionProbe.status === "loading" ? t("istanbul.inspecting") : t("istanbul.inspect")}
          </button>
          <ProbeError probe={transactionProbe} />
          {transactionProbe.status === "ok" ? (
            <div className="istanbul-result">
              <div className="istanbul-result-title">
                <strong>{t("istanbul.transaction.type", { type: transactionProbe.value.tx_type })}</strong>
                <span>
                  {t("istanbul.transaction.signerPolicy", {
                    policy: t(`istanbul.transaction.policy.${transactionProbe.value.signer_policy}`),
                  })}
                </span>
              </div>
              <dl className="istanbul-facts">
                <div><dt>{t("istanbul.fact.gasMax")}</dt><dd>{transactionProbe.value.gas_max ?? t("common.notAvailable")}</dd></div>
                <div><dt>{t("istanbul.fact.fee")}</dt><dd>{transactionProbe.value.fee}</dd></div>
                <div><dt>{t("istanbul.fact.actions")}</dt><dd>{transactionProbe.value.actions.length}</dd></div>
                <div><dt>{t("istanbul.fact.requiredSigners")}</dt><dd>{transactionProbe.value.required_signers.length}</dd></div>
              </dl>
              <span className="istanbul-label">{t("istanbul.transaction.mainAddress")}</span>
              <code>{transactionProbe.value.main_address}</code>
              <span className="istanbul-label">{t("istanbul.transaction.bodyHash")}</span>
              <code>{transactionProbe.value.body_sha256}</code>
              {transactionProbe.value.required_signers.length > 0 ? (
                <div>
                  <span className="istanbul-label">{t("istanbul.fact.requiredSigners")}</span>
                  {transactionProbe.value.required_signers.map((signer) => <code key={signer}>{signer}</code>)}
                </div>
              ) : null}
              <div className="istanbul-action-list">
                {transactionProbe.value.actions.map((action, index) => (
                  <details key={`${action.kind}-${index}`}>
                    <summary>
                      {t("istanbul.transaction.action", {
                        index: index + 1,
                        kind: action.kind,
                        description: action.description,
                      })}
                    </summary>
                    <pre>{JSON.stringify(action.canonical_json, null, 2)}</pre>
                  </details>
                ))}
              </div>
              {transactionProbe.value.tx_type === 4 ? (
                <p className="istanbul-notice">{t("istanbul.type4Disabled")}</p>
              ) : null}
            </div>
          ) : null}
        </form>
      </div>
    </section>
  );
}
