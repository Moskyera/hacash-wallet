/// <reference types="vite/client" />

declare module "*.jpg" {
  const src: string;
  export default src;
}

declare module "*.jpeg" {
  const src: string;
  export default src;
}

declare module "*.png" {
  const src: string;
  export default src;
}
/**
 * Injected by vite.config.ts. Identifies the build running on a device, so a report of
 * "nothing changed" can be told apart from "the wrong file was installed".
 */
declare const __BUILD_ID__: string;
