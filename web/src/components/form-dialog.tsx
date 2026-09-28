import { useId, type ReactNode } from "react";
import { Button, Dialog, DialogClose, DialogDescription, DialogRoot, DialogTitle, Text } from "@cloudflare/kumo";

/**
 * A create form in a dialog. The screen owns the fields, their state and
 * the mutation; this owns the frame: the title the dialog is named by,
 * the refusal shown where the person is looking, and the two ways out.
 * Escape, the Cancel button and a click outside close it without sending
 * anything, and Kumo hands focus back to whatever opened it.
 *
 * It closes only when the screen says so, which a screen does from the
 * mutation's onSuccess: a form that vanished before the server answered
 * would have nowhere to show a refusal.
 */
export function FormDialog({
  open,
  onOpenChange,
  title,
  description,
  submitLabel,
  pending,
  error,
  canSubmit = true,
  onSubmit,
  size = "lg",
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  submitLabel: string;
  pending: boolean;
  error: string | null;
  /** False while the form is not worth sending yet (a required choice left open). */
  canSubmit?: boolean;
  onSubmit: () => void;
  size?: "base" | "lg" | "xl";
  children: ReactNode;
}) {
  return (
    <DialogRoot open={open} onOpenChange={onOpenChange}>
      <Dialog size={size} className="grid max-h-[calc(100dvh-4rem)] gap-4 overflow-y-auto p-6 sm:max-h-[calc(100dvh-8rem)]">
        <DialogTitle className="text-lg font-semibold">{title}</DialogTitle>
        {description && (
          <DialogDescription>
            <Text as="span" variant="secondary">
              {description}
            </Text>
          </DialogDescription>
        )}
        <form
          className="grid gap-4"
          aria-label={title}
          onSubmit={(e) => {
            e.preventDefault();
            onSubmit();
          }}
        >
          {children}
          {error && (
            <div role="alert" className="rounded-md bg-kumo-tint px-4 py-3 ring ring-kumo-line">
              <Text>{error}</Text>
            </div>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            <DialogClose render={<Button type="button" />}>Cancel</DialogClose>
            <Button type="submit" variant="primary" disabled={pending || !canSubmit}>
              {submitLabel}
            </Button>
          </div>
        </form>
      </Dialog>
    </DialogRoot>
  );
}

/**
 * A screen's or a section's heading with the button that adds to it on
 * the right. The same button goes on the empty state, so the first thing
 * somebody sees on an empty screen is the way to fill it.
 */
export function HeaderWithAction({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="grid min-w-0 flex-1 gap-1.5">{children}</div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

/**
 * What an empty list says, and the button that starts filling it: a
 * headline, one sentence, one action. It sits where the list's first item
 * would, in the same card, so the screen does not move when the first one
 * arrives. `as` is the headline's level under the screen's own headings.
 */
export function EmptyState({
  title,
  as = "h2",
  children,
  action,
}: {
  title?: string;
  as?: "h2" | "h3";
  children: ReactNode;
  action?: ReactNode;
}) {
  const titleId = useId();
  // A titled empty state is a region named by its headline, so the action
  // in it is found as the one belonging to that emptiness.
  return (
    <div
      role={title ? "region" : undefined}
      aria-labelledby={title ? titleId : undefined}
      className="grid justify-items-start gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"
    >
      <div className="grid gap-1">
        {title && (
          <Text as={as} bold id={titleId}>
            {title}
          </Text>
        )}
        <Text variant="secondary">{children}</Text>
      </div>
      {action}
    </div>
  );
}
