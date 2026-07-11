import { api, type SendOptions } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import type { PaymentQrPayload } from "../paymentQr";

export type PaymentPayloadResult = {
  sendTo: string;
  sendAmount: string;
  preview: Awaited<ReturnType<typeof api.previewSend>> | null;
};

type ApplyOpts = {
  payload: PaymentQrPayload;
  sendOptions: SendOptions;
  toast: (msg: string, kind: "success" | "info" | "error") => void;
  withAmountMessage: string;
  withoutAmountMessage: string;
};

export async function applyPaymentPayload(opts: ApplyOpts): Promise<PaymentPayloadResult> {
  const { payload, sendOptions, toast, withAmountMessage, withoutAmountMessage } = opts;
  const amount = payload.amount_mei;
  if (amount != null && amount > 0) {
    try {
      const preview = await api.previewSend(payload.address, amount, sendOptions);
      toast(withAmountMessage, "info");
      return { sendTo: payload.address, sendAmount: String(amount), preview };
    } catch (e) {
      toast(formatInvokeError(e), "error");
      return { sendTo: payload.address, sendAmount: String(amount), preview: null };
    }
  }
  toast(withoutAmountMessage, "info");
  return { sendTo: payload.address, sendAmount: "", preview: null };
}