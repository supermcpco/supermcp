import type { ReactNode } from "react";
import { Banner, Button, DeleteResource, Dialog, DialogClose, DialogDescription, DialogRoot, DialogTitle } from "@cloudflare/kumo";

/**
 * Asks before something is deleted for good, the way the connector
 * page's "Remove" does: the dialog names the thing, and the button stays
 * disabled until its name is typed. The screen owns the mutation; this
 * owns the question.
 *
 * It cannot be closed while the deletion is under way, so a refusal from
 * the server lands in the dialog it was asked from rather than nowhere.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  resourceType,
  resourceName,
  confirmLabel,
  pending,
  error,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** What kind of thing it is, as the dialog names it: "Rule", "Service account". */
  resourceType: string;
  /** The thing's own name, which is also what has to be typed. */
  resourceName: string;
  /** The words on the button that deletes: "Delete rule". */
  confirmLabel: string;
  pending: boolean;
  error?: string | null;
  onConfirm: () => void;
}) {
  return (
    <DeleteResource
      open={open}
      onOpenChange={(next) => !pending && onOpenChange(next)}
      resourceType={resourceType}
      resourceName={resourceName}
      deleteButtonText={confirmLabel}
      isDeleting={pending}
      errorMessage={error ?? undefined}
      onDelete={onConfirm}
    />
  );
}

/**
 * Asks before something is done that cannot be taken back but is not a
 * deletion: revoking a key, stopping a delivery. The same frame as
 * `ConfirmDialog`, without the name to type, since nothing is destroyed
 * that the list would no longer show. The dialog says in `children` what
 * will happen; the button says it in two words.
 *
 * Like `ConfirmDialog`, it cannot be closed while the action is under way,
 * and a refusal from the server lands in it.
 */
export function ConfirmAction({
  open,
  onOpenChange,
  title,
  confirmLabel,
  pending,
  error,
  onConfirm,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The question, naming the thing: "Revoke Claude Desktop?". */
  title: string;
  /** The words on the button that does it: "Revoke". */
  confirmLabel: string;
  pending: boolean;
  error?: string | null;
  onConfirm: () => void;
  /** What doing it means, in a sentence or two. */
  children: ReactNode;
}) {
  return (
    <DialogRoot open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <Dialog className="p-0">
        <div className="border-b border-kumo-line px-6 py-4">
          <DialogTitle className="text-lg font-semibold">{title}</DialogTitle>
        </div>
        <div className="flex flex-col gap-2 p-6">
          {error && (
            <Banner role="alert" variant="error">
              {error}
            </Banner>
          )}
          <DialogDescription className="max-w-prose text-base text-pretty text-kumo-subtle">{children}</DialogDescription>
        </div>
        <div className="flex justify-end gap-3 border-t border-kumo-line px-6 py-4">
          <DialogClose render={<Button variant="secondary" disabled={pending} />}>Cancel</DialogClose>
          <Button variant="destructive" onClick={onConfirm} disabled={pending} loading={pending}>
            {confirmLabel}
          </Button>
        </div>
      </Dialog>
    </DialogRoot>
  );
}
