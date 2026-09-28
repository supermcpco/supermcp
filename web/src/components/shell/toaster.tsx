import { Button, Toast, cn, useKumoToastManager } from "@cloudflare/kumo";
import { CheckCircle, Info, WarningOctagon, X } from "@phosphor-icons/react";
import { toasts, type ToastKind } from "./toast";

/**
 * Where confirmations appear. The viewport is a labelled live region, so
 * each one is announced as well as shown. Mount it once, outside anything
 * that unmounts on navigation.
 *
 * This is Kumo's Toasty drawn from Kumo's own toast parts, for one
 * difference: Toasty gives every toast the role `dialog` (`alertdialog`
 * when it is an error) and takes no prop to change that. A confirmation is
 * not a dialog, so here it is a `status`, and an error an `alert`. The
 * classes are Toasty's, trimmed to what `toast()` uses: a title and a kind.
 */
export function Toaster() {
  return (
    <Toast.Provider toastManager={toasts}>
      <Toast.Portal>
        <Toast.Viewport className="fixed top-auto right-4 bottom-4 z-1 mx-auto flex w-[calc(100%-2rem)] sm:right-8 sm:bottom-8 sm:w-[340px]">
          <ToastList />
        </Toast.Viewport>
      </Toast.Portal>
    </Toast.Provider>
  );
}

const look: Record<ToastKind, { root: string; tint: string; icon: typeof CheckCircle; close: string }> = {
  success: {
    root: "ring-[0.3px] ring-kumo-success bg-kumo-base [&_[data-toast-icon]]:text-kumo-success [&_[data-toast-title]]:text-kumo-success",
    tint: "bg-kumo-success-tint/20",
    icon: CheckCircle,
    close: "text-kumo-success",
  },
  error: {
    root: "ring-[0.3px] ring-kumo-danger bg-kumo-base [&_[data-toast-icon]]:text-kumo-danger [&_[data-toast-title]]:text-kumo-danger",
    tint: "bg-kumo-danger-tint/50",
    icon: WarningOctagon,
    close: "text-kumo-danger",
  },
  info: {
    root: "ring-[0.3px] ring-kumo-info bg-kumo-control [&_[data-toast-icon]]:text-kumo-info [&_[data-toast-title]]:text-kumo-info",
    tint: "bg-kumo-info-tint/50",
    icon: Info,
    close: "text-kumo-info",
  },
};

function kindOf(variant: unknown): ToastKind {
  return variant === "error" || variant === "info" ? variant : "success";
}

function ToastList() {
  const { toasts: shown } = useKumoToastManager();
  return shown.map((t) => {
    const kind = kindOf(t.variant);
    const { root, tint, icon: Icon, close } = look[kind];
    return (
      <Toast.Root
        key={t.id}
        toast={t}
        role={kind === "error" ? "alert" : "status"}
        // Base UI's dialog attribute; it has no meaning on a status.
        aria-modal={undefined}
        className={cn(
          "absolute right-0 bottom-0 left-auto z-[calc(1000-var(--toast-index))] mr-0 h-[var(--height)] w-full origin-bottom select-none",
          "rounded-xl ring ring-kumo-line bg-clip-padding p-4 shadow-lg",
          root,
          "[--gap:0.75rem] [--height:var(--toast-frontmost-height,var(--toast-height))] [--offset-y:calc(var(--toast-offset-y)*-1+calc(var(--toast-index)*var(--gap)*-1)+var(--toast-swipe-movement-y))] [--peek:0.75rem] [--scale:calc(max(0,1-(var(--toast-index)*0.1)))] [--shrink:calc(1-var(--scale))]",
          "[transform:translateX(var(--toast-swipe-movement-x))_translateY(calc(var(--toast-swipe-movement-y)-(var(--toast-index)*var(--peek))-(var(--shrink)*var(--height))))_scale(var(--scale))] [transition:transform_0.5s_cubic-bezier(0.22,1,0.36,1),opacity_0.5s,height_0.15s]",
          "after:absolute after:top-full after:left-0 after:h-[calc(var(--gap)+1px)] after:w-full after:content-['']",
          "data-[ending-style]:opacity-0 data-[expanded]:h-[var(--toast-height)] data-[expanded]:[transform:translateX(var(--toast-swipe-movement-x))_translateY(calc(var(--offset-y)))] data-[limited]:opacity-0 data-[starting-style]:[transform:translateY(150%)]",
          "data-[ending-style]:data-[swipe-direction=down]:[transform:translateY(calc(var(--toast-swipe-movement-y)+150%))] data-[expanded]:data-[ending-style]:data-[swipe-direction=down]:[transform:translateY(calc(var(--toast-swipe-movement-y)+150%))]",
          "data-[ending-style]:data-[swipe-direction=right]:[transform:translateX(calc(var(--toast-swipe-movement-x)+150%))_translateY(var(--offset-y))] data-[expanded]:data-[ending-style]:data-[swipe-direction=right]:[transform:translateX(calc(var(--toast-swipe-movement-x)+150%))_translateY(var(--offset-y))]",
          "[&[data-ending-style]:not([data-limited]):not([data-swipe-direction])]:[transform:translateY(150%)]",
          t.bump && "animate-toast-bump",
        )}
      >
        <div className={cn("absolute inset-0 rounded-xl bg-kumo-base/90", tint)} />
        <Toast.Content className="isolate flex flex-col gap-1 transition-opacity [transition-duration:250ms] data-[behind]:pointer-events-none data-[behind]:opacity-0 data-[expanded]:pointer-events-auto data-[expanded]:opacity-100">
          <div className="flex items-start gap-2">
            <Icon data-toast-icon className="mt-0.5 h-4 w-4 shrink-0" weight="fill" aria-hidden />
            <div className="flex flex-col gap-1 overflow-hidden">
              <Toast.Title data-toast-title className="text-[0.975rem] leading-5 font-medium text-kumo-default" />
            </div>
          </div>
          <Toast.Close
            aria-label="Close"
            // Base UI hides the button from assistive technology until the
            // stack is expanded, yet leaves it in the tab order; axe
            // rightly calls a focusable hidden control a fault. Kumo's
            // dialog role only masked it, as axe treats an open dialog as
            // modal. Visible to everyone, it is simply the way to close it.
            aria-hidden={undefined}
            render={
              <Button
                variant="ghost"
                size="sm"
                shape="square"
                aria-label="Close"
                className={cn("absolute top-2 right-2 size-5 rounded text-kumo-subtle hover:bg-current/15", close)}
                icon={<X className="h-3 w-3" aria-hidden />}
              />
            }
          />
        </Toast.Content>
      </Toast.Root>
    );
  });
}
