import { Toasty } from "@cloudflare/kumo";
import { toasts } from "./toast";

/**
 * Where confirmations appear. Kumo's viewport is a labelled live region,
 * so each one is announced as well as shown. Mount it once, outside
 * anything that unmounts on navigation.
 */
export function Toaster() {
  return <Toasty toastManager={toasts}>{null}</Toasty>;
}
