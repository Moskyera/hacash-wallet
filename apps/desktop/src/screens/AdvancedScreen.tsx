import { useState } from "react";
import { Hip23PatternCheck } from "../api";
import { ISTANBUL_HEIGHT } from "./types";

type Props = {
  busy: boolean;
  onValidate: (params: {
    hipTxType: string;
    hipChainHeight: string;
    hipGasMax: string;
    hipHasAssetTex: boolean;
    hipAstDepth: string;
    hipGuardOnly: boolean;
    hipActionCount: string;
    includeP2: boolean;
    hipP2Start: string;
    hipP2End: string;
    hipP2GuardBeforeDebit: boolean;
    includeP3: boolean;
    hipP3Floor: string;
    hipP3DebitBeforeFloor: boolean;
  }) => Promise<Hip23PatternCheck[] | null>;
};

function renderHip23Result(check: Hip23PatternCheck) {
  return (
    <div
      key={check.pattern}
      className={`preview-card ${check.check.ok ? "result-ok" : "result-fail"}`}
    >
      <h4>
        {check.pattern} — {check.check.ok ? "OK" : "Failed"}
      </h4>
      {check.check.errors.length > 0 && (
        <div className="warn-box">
          <strong>Errors</strong>
          <ul>
            {check.check.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </div>
      )}
      {check.check.warnings.length > 0 && (
        <div className="info-box">
          <strong>Warnings</strong>
          <ul>
            {check.check.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function AdvancedScreen({ busy, onValidate }: Props) {
  const [hipTxType, setHipTxType] = useState("3");
  const [hipChainHeight, setHipChainHeight] = useState(String(ISTANBUL_HEIGHT));
  const [hipGasMax, setHipGasMax] = useState("100");
  const [hipHasAssetTex, setHipHasAssetTex] = useState(false);
  const [hipAstDepth, setHipAstDepth] = useState("0");
  const [hipGuardOnly, setHipGuardOnly] = useState(false);
  const [hipActionCount, setHipActionCount] = useState("1");
  const [includeP2, setIncludeP2] = useState(false);
  const [hipP2Start, setHipP2Start] = useState("0");
  const [hipP2End, setHipP2End] = useState("0");
  const [hipP2GuardBeforeDebit, setHipP2GuardBeforeDebit] = useState(true);
  const [includeP3, setIncludeP3] = useState(false);
  const [hipP3Floor, setHipP3Floor] = useState("1");
  const [hipP3DebitBeforeFloor, setHipP3DebitBeforeFloor] = useState(true);
  const [hipResults, setHipResults] = useState<Hip23PatternCheck[] | null>(null);

  return (
    <section className="panel">
      <h2>HIP-23 Type3 pattern validator</h2>
      <p className="muted">
        Validate universal, P2 (HeightScope), and P3 (BalanceFloor) checklist patterns
        before signing complex Type-3 transactions.
      </p>

      <div className="form-section">
        <h3>Universal</h3>
        <div className="two-col">
          <div>
            <label>tx_type</label>
            <input
              type="number"
              min="0"
              value={hipTxType}
              onChange={(e) => setHipTxType(e.target.value)}
            />
          </div>
          <div>
            <label>chain_height</label>
            <input
              type="number"
              min="0"
              value={hipChainHeight}
              onChange={(e) => setHipChainHeight(e.target.value)}
            />
          </div>
        </div>
        <div className="two-col">
          <div>
            <label>gas_max</label>
            <input
              type="number"
              min="0"
              value={hipGasMax}
              onChange={(e) => setHipGasMax(e.target.value)}
            />
          </div>
          <div>
            <label>ast_depth</label>
            <input
              type="number"
              min="0"
              value={hipAstDepth}
              onChange={(e) => setHipAstDepth(e.target.value)}
            />
          </div>
        </div>
        <div>
          <label>action_count</label>
          <input
            type="number"
            min="0"
            value={hipActionCount}
            onChange={(e) => setHipActionCount(e.target.value)}
          />
        </div>
        <label className="check-row">
          <input
            type="checkbox"
            checked={hipHasAssetTex}
            onChange={(e) => setHipHasAssetTex(e.target.checked)}
          />
          has_asset_tex
        </label>
        <label className="check-row">
          <input
            type="checkbox"
            checked={hipGuardOnly}
            onChange={(e) => setHipGuardOnly(e.target.checked)}
          />
          guard_only
        </label>
      </div>

      <div className="form-section">
        <label className="check-row">
          <input
            type="checkbox"
            checked={includeP2}
            onChange={(e) => setIncludeP2(e.target.checked)}
          />
          Include P2 (HeightScope)
        </label>
        {includeP2 && (
          <>
            <div className="two-col">
              <div>
                <label>start</label>
                <input
                  type="number"
                  min="0"
                  value={hipP2Start}
                  onChange={(e) => setHipP2Start(e.target.value)}
                />
              </div>
              <div>
                <label>end (0 = open-ended)</label>
                <input
                  type="number"
                  min="0"
                  value={hipP2End}
                  onChange={(e) => setHipP2End(e.target.value)}
                />
              </div>
            </div>
            <label className="check-row">
              <input
                type="checkbox"
                checked={hipP2GuardBeforeDebit}
                onChange={(e) => setHipP2GuardBeforeDebit(e.target.checked)}
              />
              guard_before_debit
            </label>
          </>
        )}
      </div>

      <div className="form-section">
        <label className="check-row">
          <input
            type="checkbox"
            checked={includeP3}
            onChange={(e) => setIncludeP3(e.target.checked)}
          />
          Include P3 (BalanceFloor)
        </label>
        {includeP3 && (
          <>
            <label>floor_hacash_mei</label>
            <input
              type="number"
              min="0"
              step="0.001"
              value={hipP3Floor}
              onChange={(e) => setHipP3Floor(e.target.value)}
            />
            <label className="check-row">
              <input
                type="checkbox"
                checked={hipP3DebitBeforeFloor}
                onChange={(e) => setHipP3DebitBeforeFloor(e.target.checked)}
              />
              debit_before_floor
            </label>
          </>
        )}
      </div>

      <button
        disabled={busy}
        onClick={() =>
          void onValidate({
            hipTxType,
            hipChainHeight,
            hipGasMax,
            hipHasAssetTex,
            hipAstDepth,
            hipGuardOnly,
            hipActionCount,
            includeP2,
            hipP2Start,
            hipP2End,
            hipP2GuardBeforeDebit,
            includeP3,
            hipP3Floor,
            hipP3DebitBeforeFloor,
          }).then((results) => {
            if (results) setHipResults(results);
          })
        }
      >
        Run validation
      </button>
      {hipResults?.map(renderHip23Result)}
    </section>
  );
}