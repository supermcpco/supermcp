import { DeleteResource } from "@cloudflare/kumo";

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
