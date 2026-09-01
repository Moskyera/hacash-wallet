/**
 * A real mount, with effects, for tests that need one.
 *
 * The desktop suite renders with `renderToStaticMarkup`, which never runs
 * `useEffect` and never re-renders. A whole family of defects lives in exactly
 * that gap: state seeded once from a prop that is still empty at mount and never
 * resynced when the prop arrives. `renderToStaticMarkup` cannot see any of them,
 * because it only ever performs a first mount with final props, which is the one
 * ordering the real app never has.
 *
 * `mountComponent` gives a test the ordering the app really has: mount with the
 * props that exist at mount, flush effects, then rerender with the props that
 * arrive later.
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import type { ReactElement } from "react";

export type Mounted = {
  container: HTMLElement;
  /** Render again with different props, then flush effects. */
  rerender: (next: ReactElement) => void;
  unmount: () => void;
  /** Every rendered control, in document order. */
  buttons: () => HTMLButtonElement[];
  /** The first button whose visible text contains `text`. */
  button: (text: string) => HTMLButtonElement | undefined;
  input: (selector: string) => HTMLInputElement | null;
  text: () => string;
  html: () => string;
};

// React 19 checks this before it will run `act`.
(globalThis as Record<string, unknown>).IS_REACT_ACT_ENVIRONMENT = true;

export function mountComponent(element: ReactElement): Mounted {
  const container = document.createElement("div");
  document.body.appendChild(container);
  let root: Root;
  act(() => {
    root = createRoot(container);
    root.render(element);
  });
  const buttons = () => Array.from(container.querySelectorAll("button"));
  return {
    container,
    rerender: (next: ReactElement) => {
      act(() => {
        root.render(next);
      });
    },
    unmount: () => {
      act(() => {
        root.unmount();
      });
      container.remove();
    },
    buttons,
    button: (text: string) =>
      buttons().find((node) => (node.textContent ?? "").includes(text)),
    input: (selector: string) => container.querySelector(selector),
    text: () => container.textContent ?? "",
    html: () => container.innerHTML,
  };
}

/** Type into a controlled input the way a person does, firing React's onChange. */
export function typeInto(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  )?.set;
  act(() => {
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

/** Press a control and flush whatever it schedules. */
export function click(node: Element): void {
  act(() => {
    node.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
  });
}

/** Let pending promise callbacks and the effects they schedule settle. */
export async function settle(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}
