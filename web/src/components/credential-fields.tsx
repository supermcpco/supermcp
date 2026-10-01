import { useId } from "react";
import { Input, Text } from "@cloudflare/kumo";
import { stillNeeded, type CredentialField } from "../lib/connector";

/**
 * One field per credential, and the line that says which are still
 * needed. The catalog's install form and a connector's own page both use
 * it, so a credential is asked for the same way wherever it is given.
 *
 * Values are sealed on the way into the database and never come back out:
 * a credential the connector already holds shows as set, with an empty
 * field that replaces it only if something is typed.
 */
export function CredentialFields({
  fields,
  values,
  onChange,
  disabled,
  bare,
}: {
  fields: readonly CredentialField[];
  values: Record<string, string>;
  onChange: (values: Record<string, string>) => void;
  disabled?: boolean;
  /** Drawn without a card of its own, for a form that already sits in one. */
  bare?: boolean;
}) {
  const missing = stillNeeded(fields, values);
  // Each input is named by its credential's name and described by its
  // description, through ids Kumo can see.
  const ids = useId();
  return (
    <div className={bare ? "grid gap-3" : "grid gap-3 rounded-lg px-5 py-4 ring ring-kumo-line"}>
      {fields.map((c, i) => (
        <label key={c.name} className="grid gap-1.5">
          <span className="font-mono text-[0.9em]" id={`${ids}-${i}-name`}>
            {c.name}
            {!c.required && <span className="font-sans"> (optional)</span>}
            {c.set && <span className="font-sans"> (set; type to replace it)</span>}
          </span>
          {c.description && (
            <Text variant="secondary" id={`${ids}-${i}-description`}>
              {c.description}
            </Text>
          )}
          <Input
            aria-labelledby={`${ids}-${i}-name`}
            aria-describedby={c.description ? `${ids}-${i}-description` : undefined}
            type={c.secret === false ? "text" : "password"}
            autoComplete="off"
            disabled={disabled}
            value={values[c.name] ?? ""}
            onChange={(e) => onChange({ ...values, [c.name]: e.target.value })}
          />
        </label>
      ))}
      {missing.length > 0 && <Text variant="secondary">Still needed: {missing.join(", ")}.</Text>}
    </div>
  );
}
