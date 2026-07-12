/** Apply top/bottom insets so headers clear the OS status bar (edge-to-edge Android/iOS). */
export function installSafeAreaInsets(): void {
  const root = document.documentElement;

  const measureInset = (edge: "top" | "bottom"): number => {
    const el = document.createElement("div");
    el.style.cssText = `position:fixed;${edge}:0;left:0;padding-${edge}:env(safe-area-inset-${edge});visibility:hidden;pointer-events:none;`;
    document.body.appendChild(el);
    const px = parseFloat(getComputedStyle(el).getPropertyValue(`padding-${edge}`)) || 0;
    el.remove();
    return px;
  };

  const isMobileUa = /android|iphone|ipad|ipod/i.test(navigator.userAgent);
  const isTauri = "__TAURI_INTERNALS__" in window || "__TAURI__" in window;

  const apply = () => {
    let top = measureInset("top");
    if (top < 1 && (isMobileUa || isTauri)) {
      // Android WebView + edge-to-edge often reports 0 despite content under the status bar.
      top = 36;
    }
    root.style.setProperty("--safe-top", `${top}px`);

    let bottom = measureInset("bottom");
    root.style.setProperty("--safe-bottom", `${bottom}px`);
  };

  apply();
  window.visualViewport?.addEventListener("resize", apply);
  window.addEventListener("orientationchange", apply);
}